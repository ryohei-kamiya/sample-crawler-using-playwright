import argparse
import re
import traceback
import random
import os
import signal
import sys
import seccomp
import inspect
import asyncio
import uuid
import idna
import hashlib
from typing import Any
from urllib.parse import urlparse, quote
from playwright.async_api import async_playwright
from multiprocessing import Pool, TimeoutError


def url2dirpath(url: str) -> str:
    parsed_url = urlparse(url)
    hostname = (
        idna.encode(parsed_url.hostname).decode("utf-8") if parsed_url.hostname else ""
    )
    path = parsed_url.path if parsed_url.path else ""
    path = path.strip("/")
    query = quote(parsed_url.query) if parsed_url.query else ""
    fragment = quote(parsed_url.fragment) if parsed_url.fragment else ""
    h = hashlib.new("sha256")
    if len(path) > 512:
        parts = []
        for part in path.split("/"):
            if len(part) > 255:
                h.update(bytes(part, "utf-8"))
                part = h.hexdigest()
            parts.append(part)
        path = "/".join(parts)
        if len(path) > 512:
            path = path[:512]
    if len(query) > 255:
        h.update(bytes(query, "utf-8"))
        query = h.hexdigest()
    if len(fragment) > 255:
        h = hashlib.new("sha256")
        h.update(bytes(fragment, "utf-8"))
        fragment = h.hexdigest()
    result = "/".join([hostname, path, query, fragment])
    result = re.sub(r"[^\-0-9a-zA-Z\./]", "_", result)
    result = result.strip("/")
    return result


def makedir(dirpath: str):
    os.makedirs(dirpath, exist_ok=True)


def output(data: Any, filepath: str):
    with open(filepath, "w") as fout:
        if type(data) == str:
            fout.write(data)
        elif type(data) == list or type(data) == set:
            for line in data:
                line = line.strip()
                if not line:  # 空文字は出力しない
                    continue
                fout.write(f"{line}\n")
        elif type(data) == dict:
            for key, value in data.items():
                key = key.strip()
                if not key:  # 空文字は出力しない
                    continue
                value = value.strip()
                fout.write(f"{key} => {value}\n")


def sigsys_handler(signum, frame):
    # スタックフレーム情報を取得
    frame_info = inspect.getframeinfo(frame)

    # ファイル名、行番号、関数名を取得
    filename = frame_info.filename
    line_number = frame_info.lineno
    function_name = frame_info.function

    print(
        f"{filename}:{line_number}:{function_name} Unauthorized system call ({signum}) invoked.",
        file=sys.stderr,
    )
    sys.exit(1)


async def crawl_page(
    browser_type_str: str, url: str
) -> tuple[str, set[str], dict[str, str], dict[str, str]]:
    async with async_playwright() as p:
        browser_type = p.chromium
        if browser_type_str == "firefox":
            browser_type = p.firefox
        elif browser_type_str == "webkit":
            browser_type = p.webkit
        browser = await browser_type.launch(headless=True)  # デフォルトでsandboxが有効
        context = await browser.new_context()

        redirected_urls: dict[str, str] = {}
        js_files: dict[str, str] = {}

        def response_handler(response):
            # リダイレクトを検出
            if 300 <= response.status < 400 and response.headers.get("location"):
                redirected_urls[response.url] = response.headers["location"]
            # JavaScriptファイルの内容を取得
            if response.request.resource_type == "script":
                if response.ok and js_files.get(response.url, None) is None:
                    asyncio.create_task(get_js_content(response))

        async def get_js_content(response):
            if not js_files.get(response.url):
                content = await response.text()
                js_files[response.url] = content

        context.on("response", response_handler)  # 全てのコンテンツのresponseイベントを捕捉

        page = await context.new_page()

        await page.goto(url)  # ページ読み込みが完了するまで待機
        print(f"[GET]{url}")

        # ページ内のコンテンツを取得
        content: str = await page.content()

        sub_links: set[str] = set()

        # ページ遷移とメディアデータ取得をキャンセルするイベントリスナーを設定
        async def cancel_requests(route):
            request = route.request
            if request.resource_type == "document":
                sub_links.add(request.url)  # ページ内のリンクリストを収集
                await route.abort()  # ページ遷移をキャンセル
            elif request.resource_type == "image":
                await route.abort()  # イメージデータ取得をキャンセル
            elif request.resource_type == "media":
                await route.abort()  # メディアデータ取得をキャンセル
            else:
                await route.continue_()  # その他のリクエストは継続

        await page.route("**", cancel_requests)  # ページ遷移とメディアデータ取得をキャンセル

        # JavaScriptファイルの動的検知のため、以下の操作をページ上で実行
        # 処理1. スムーズスクロール
        # 処理2. 数秒待機
        # 処理3. リンクを動的に検出してクリック

        # 処理1. スムーズスクロール
        await page.evaluate(
            "window.scrollTo({top: document.body.scrollHeight, left: 0, behavior: 'smooth'})"
        )

        # 処理2. 数秒(3秒)待機
        await asyncio.sleep(3)

        # 処理3. リンクを動的に検出してクリック
        linkelems = await page.query_selector_all("a")
        for linkelem in linkelems:
            if (
                await linkelem.is_visible()
                and await linkelem.is_enabled()
                and await linkelem.evaluate("el => document.body.contains(el)")
            ):
                sub_url = await linkelem.get_attribute("href")
                if sub_url and type(sub_url) is str:
                    try:
                        await linkelem.click(timeout=5000)  # クリック後、最長5秒待機
                    except asyncio.TimeoutError:
                        # ページ遷移がキャンセルされた場合、タイムアウトエラーが発生するので無視
                        pass

        await page.close()
        await context.close()
        await browser.close()

        return content, sub_links, redirected_urls, js_files


def crawl_page_in_sandbox(
    browser_type_str: str, url: str
) -> tuple[str, set[str], dict[str, str], dict[str, str]]:
    signal.signal(signal.SIGSYS, sigsys_handler)

    # seccomp のフィルターを作成
    filter = seccomp.SyscallFilter(defaction=seccomp.KILL)

    # 指定されたシステムコールを許可
    allowed_syscalls = [
        "_llseek",
        "_newselect",
        "accept",
        "accept4",
        "access",
        "arch_prctl",
        "arm_fadvise64_64",
        "arm_sync_file_range",
        "bind",
        "bpf",
        "brk",
        "capget",
        "capset",
        "chdir",
        "chmod",
        "chown",
        "chown32",
        "clock_adjtime",
        "clock_adjtime64",
        "clock_getres",
        "clock_getres_time64",
        "clock_gettime",
        "clock_gettime64",
        "clock_nanosleep",
        "clock_nanosleep_time64",
        "clock_settime",
        "clone",
        "close",
        "connect",
        "copy_file_range",
        "creat",
        "dup",
        "dup2",
        "dup3",
        "epoll_create",
        "epoll_create1",
        "epoll_ctl",
        "epoll_ctl_old",
        "epoll_pwait",
        "epoll_wait",
        "epoll_wait_old",
        "eventfd",
        "eventfd2",
        "execve",
        "execveat",
        "exit",
        "exit_group",
        "faccessat",
        "faccessat2",
        "fadvise64",
        "fadvise64_64",
        "fallocate",
        "fanotify_init",
        "fanotify_mark",
        "fchdir",
        "fchmod",
        "fchmodat",
        "fchown",
        "fchown32",
        "fchownat",
        "fcntl",
        "fcntl64",
        "fdatasync",
        "fgetxattr",
        "flistxattr",
        "flock",
        "fremovexattr",
        "fsetxattr",
        "fstat",
        "fstat64",
        "fstatat64",
        "fstatfs",
        "fstatfs64",
        "fsync",
        "ftruncate",
        "ftruncate64",
        "futex",
        "futex_time64",
        "futimesat",
        "get_robust_list",
        "get_thread_area",
        "getcpu",
        "getcwd",
        "getdents",
        "getdents64",
        "getegid",
        "getegid32",
        "geteuid",
        "geteuid32",
        "getgid",
        "getgid32",
        "getgroups",
        "getgroups32",
        "getitimer",
        "getpeername",
        "getpgid",
        "getpgrp",
        "getpid",
        "getppid",
        "getpriority",
        "getrandom",
        "getresgid",
        "getresgid32",
        "getresuid",
        "getresuid32",
        "getrlimit",
        "getrusage",
        "getsid",
        "getsockname",
        "getsockopt",
        "gettid",
        "gettimeofday",
        "getuid",
        "getuid32",
        "getxattr",
        "inotify_add_watch",
        "inotify_init",
        "inotify_init1",
        "inotify_rm_watch",
        "io_pgetevents",
        "io_pgetevents_time64",
        "io_uring_enter",
        "io_uring_register",
        "io_uring_setup",
        "ioctl",
        "ioprio_get",
        "ioprio_set",
        "ipc",
        "kill",
        "lchown",
        "lchown32",
        "lgetxattr",
        "link",
        "linkat",
        "listen",
        "listxattr",
        "llistxattr",
        "lookup_dcookie",
        "lremovexattr",
        "lseek",
        "lsetxattr",
        "lstat",
        "lstat64",
        "madvise",
        "membarrier",
        "memfd_create",
        "mincore",
        "mkdir",
        "mkdirat",
        "mknod",
        "mknodat",
        "mlock",
        "mlock2",
        "mlockall",
        "mmap",
        "mmap2",
        "mprotect",
        "mq_getsetattr",
        "mq_notify",
        "mq_open",
        "mq_timedreceive",
        "mq_timedreceive_time64",
        "mq_timedsend",
        "mq_timedsend_time64",
        "mq_unlink",
        "mremap",
        "msgctl",
        "msgget",
        "msgrcv",
        "msgsnd",
        "msync",
        "munlock",
        "munlockall",
        "munmap",
        "nanosleep",
        "newfstatat",
        "open",
        "open_by_handle_at",
        "openat",
        "pause",
        "pipe",
        "pipe2",
        "poll",
        "ppoll",
        "ppoll_time64",
        "prctl",
        "pread64",
        "preadv",
        "preadv2",
        "prlimit64",
        "pselect6",
        "pselect6_time64",
        "pwrite64",
        "pwritev",
        "pwritev2",
        "quotactl",
        "read",
        "readahead",
        "readlink",
        "readlinkat",
        "readv",
        "recv",
        "recvfrom",
        "recvmmsg",
        "recvmmsg_time64",
        "recvmsg",
        "remap_file_pages",
        "removexattr",
        "rename",
        "renameat",
        "renameat2",
        "restart_syscall",
        "rmdir",
        "rseq",
        "rt_sigaction",
        "rt_sigpending",
        "rt_sigprocmask",
        "rt_sigqueueinfo",
        "rt_sigreturn",
        "rt_sigsuspend",
        "rt_sigtimedwait",
        "rt_sigtimedwait_time64",
        "rt_tgsigqueueinfo",
        "s390_pci_mmio_read",
        "s390_pci_mmio_write",
        "sched_get_priority_max",
        "sched_get_priority_min",
        "sched_getaffinity",
        "sched_getattr",
        "sched_getparam",
        "sched_getscheduler",
        "sched_rr_get_interval",
        "sched_rr_get_interval_time64",
        "sched_setaffinity",
        "sched_setattr",
        "sched_setparam",
        "sched_setscheduler",
        "sched_yield",
        "seccomp",
        "select",
        "semtimedop",
        "semtimedop_time64",
        "send",
        "sendfile",
        "sendfile64",
        "sendmmsg",
        "sendmsg",
        "sendto",
        "set_mempolicy",
        "set_robust_list",
        "set_thread_area",
        "set_tid_address",
        "set_tls",
        "setfsgid",
        "setfsgid32",
        "setfsuid",
        "setfsuid32",
        "setgid",
        "setgid32",
        "setgroups",
        "setgroups32",
        "setitimer",
        "setpgid",
        "setpriority",
        "setregid",
        "setregid32",
        "setresgid",
        "setresgid32",
        "setresuid",
        "setresuid32",
        "setreuid",
        "setreuid32",
        "setrlimit",
        "setsid",
        "setsockopt",
        "setuid",
        "setuid32",
        "setxattr",
        "shmat",
        "shmctl",
        "shmdt",
        "shmget",
        "shutdown",
        "sigaltstack",
        "signalfd",
        "signalfd4",
        "sigprocmask",
        "sigreturn",
        "socket",
        "socketcall",
        "socketpair",
        "splice",
        "stat",
        "stat64",
        "statfs",
        "statfs64",
        "statx",
        "symlink",
        "symlinkat",
        "sync",
        "sync_file_range",
        "sync_file_range2",
        "syncfs",
        "sysinfo",
        "tee",
        "timer_gettime64",
        "timer_settime64",
        "timerfd_create",
        "timerfd_gettime",
        "timerfd_gettime64",
        "timerfd_settime",
        "timerfd_settime64",
        "times",
        "tkill",
        "truncate",
        "truncate64",
        "ugetrlimit",
        "umask",
        "uname",
        "unlink",
        "unlinkat",
        "utime",
        "utimensat",
        "utimensat_time64",
        "utimes",
        "vfork",
        "vmsplice",
        "wait4",
        "waitid",
        "waitpid",
        "write",
        "writev",
    ]

    # firefoxは以下のシステムコールを要求する(dmesgで確認した)。
    # これらがなぜブラウザの動作に必要なのか理由が分からない。
    # firefoxは使用すべきではないかも知れない。
    # 使用した環境(Dockerイメージ)は playwright/python:v1.33.0-jammy。
    # バージョンを変えると挙動が変わる可能性あり。その際は要再評価。
    """ firefoxが追加で要求するシステムコールの一覧
        "acct": プロセスアカウンティングを有効化/無効化
        "umount2": ファイルシステムのアンマウント
        "_sysctl": カーネルパラメータを取得/設定
    """

    for syscall_name in allowed_syscalls:
        filter.add_rule(seccomp.ALLOW, syscall_name)

    # 作成したフィルターを有効化
    filter.load()

    try:
        return asyncio.run(crawl_page(browser_type_str, url))
    except Exception as e:
        print(f"Error: {url} {e}", file=sys.stderr)
        return f"Errro: {e} in {url}", set(), {}, {}


def crawl_pages(
    browser_type_str: str,
    urls: set,
    output_root_dir: str,
    target_domains: set = set(),
    processed_urls: dict = {},
    excluded_urls: set = set(),
    redirected_urls: dict = {},
    depth: int = -1,
    limit: int = 5,  # 同時にクロールするURLは5つまで
    timeout: int = 30,  # タイムアウト時間の初期値は30秒
):
    if not bool(urls):  # クロール対象URLリスト(urls)が空の場合は処理を中断
        return

    sub_urls = set()
    randomized_urls = list(urls)
    random.shuffle(randomized_urls)
    with Pool(processes=limit) as pool:
        procs = []
        for url in urls:
            if url in excluded_urls:
                continue  # excluded_urls に含まれる URL はクロール対象から除外
            procs.append(
                (url, pool.apply_async(crawl_page_in_sandbox, (browser_type_str, url)))
            )
        for proc in procs:
            try:
                url = proc[0]
                res = proc[1]
                results = res.get(timeout=timeout)

                content = results[0]
                sub_links = results[1]
                for sub_link in sub_links:
                    sub_urls.add(sub_link)

                for key, value in results[2].items():
                    redirected_urls[key] = value

                js_files = results[3]

                dirpath = url2dirpath(url)
                try:
                    makedir(
                        "/".join([output_root_dir, browser_type_str, "page", dirpath])
                    )
                except Exception:
                    dirpath = "__" + str(uuid.uuid4())
                    makedir(
                        "/".join([output_root_dir, browser_type_str, "page", dirpath])
                    )
                dirpath = "/".join([output_root_dir, browser_type_str, "page", dirpath])

                # クローリングしたHTMLデータを出力
                output(
                    content,
                    "/".join([dirpath, "content.html"]),
                )

                # ページ内のリンクリストを出力
                output(
                    sub_links,
                    "/".join([dirpath, "urls.txt"]),
                )

                # ページ内のJavaScriptファイルを出力
                for js_url, js_content in js_files.items():
                    js_dirpath = url2dirpath(js_url)
                    try:
                        makedir(
                            "/".join(
                                [output_root_dir, browser_type_str, "js", js_dirpath]
                            )
                        )
                    except Exception:
                        js_dirpath = "__" + str(uuid.uuid4())
                        makedir(
                            "/".join(
                                [output_root_dir, browser_type_str, "js", js_dirpath]
                            )
                        )
                    js_dirpath = "/".join(
                        [output_root_dir, browser_type_str, "js", js_dirpath]
                    )
                    output(  # JavaScriptのURLに対応するディレクトリに保存
                        js_content,
                        "/".join([js_dirpath, "script.js"]),
                    )
                    realfile = "/".join([js_dirpath, "script.js"])
                    linkfile = "/".join([dirpath, str(uuid.uuid4()) + ".js"])
                    os.symlink(realfile, linkfile)  # リンク元のページのディレクトリにシンボリックリンクを置く

                processed_urls[
                    url
                ] = dirpath  # クロール済みURLは、保存先ディレクトリ名と関連付けて処理済みURLリストに追加
            except TimeoutError:
                traceback.print_exc()
            except Exception:
                traceback.print_exc()

    # クロール済みリンク、外部リンクは、次のクロール対象(next_urls)から除去する
    next_urls = set()
    links = (urls | sub_urls) - set(processed_urls.keys()) - excluded_urls
    for link in links:
        link_parsed_url = urlparse(link)
        link_domain = link_parsed_url.hostname
        if link_domain in target_domains:  # クロール対象ドメイン配下のリンクのみnext_urlsに追加
            next_urls.add(link)
        else:  # 外部リンクは excluded_urlsに追加
            excluded_urls.add(link)

    if depth > 0 or depth < 0:  # 探索の深さが 0 以外の場合に、次の深さのクロールを実行
        crawl_pages(
            browser_type_str,
            next_urls,
            output_root_dir,
            target_domains,
            processed_urls,
            excluded_urls,
            redirected_urls,
            depth - 1,
            limit,
        )


def main(args):
    urls = set()
    target_domains = set()
    with open(args.urllistfile, "r") as f:
        while True:
            line = f.readline()
            if not line:
                break
            url = line.strip()
            if url.startswith("#"):
                continue
            parsed_url = urlparse(url)
            target_domain = parsed_url.hostname
            urls.add(url)
            target_domains.add(target_domain)

    for browser_type_str in args.browsers:
        processed_urls = {}
        excluded_urls = set()
        redirected_urls = {}
        makedir("/".join([args.output_root_dir, browser_type_str]))

        crawl_pages(
            browser_type_str,
            urls,
            args.output_root_dir,
            target_domains,
            processed_urls,
            excluded_urls,
            redirected_urls,
            depth=args.depth,
            limit=args.limit,
        )

        # 処理済みURLのリストを出力
        output_filepath = "/".join(
            [args.output_root_dir, browser_type_str, "all_processed_urls.txt"]
        )
        output(processed_urls, output_filepath)

        # 処理対象外URLのリストを出力
        output_filepath = "/".join(
            [args.output_root_dir, browser_type_str, "all_excluded_urls.txt"]
        )
        output(excluded_urls, output_filepath)

        # リダイレクトURLのリストを出力
        output_filepath = "/".join(
            [args.output_root_dir, browser_type_str, "all_redirected_urls.txt"]
        )
        output(redirected_urls, output_filepath)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="A sample crawler using Puppeteer")
    parser.add_argument("urllistfile", type=str, help="URL list for crawling")
    parser.add_argument(
        "--browsers",
        choices=["chromium", "firefox", "webkit"],
        nargs="*",
        default=["chromium"],
        help="Set the browsers to use",
    )
    parser.add_argument(
        "--output-root-dir",
        type=str,
        default="/tmp/crawler-output",
        help="Set output root directory",
    )
    parser.add_argument(
        "--depth", type=int, default=-1, help="Set the maximum number of sublinks"
    )
    parser.add_argument(
        "--limit", type=int, default=-1, help="Set the concurrent crawl executions"
    )
    args = parser.parse_args()
    main(args)
