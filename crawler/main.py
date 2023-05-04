import argparse
import re
import traceback
import random
import os
import signal
import sys
import seccomp
import inspect
from typing import Any
from urllib.parse import urlparse
from playwright.sync_api import sync_playwright
from multiprocessing import Pool, TimeoutError


def url2dirpath(url: str) -> str:
    result = re.sub(r"^.*://", "", url)
    result = re.sub(r"[^\-0-9a-zA-Z\./]", "_", result)
    result = result.strip("/ ")
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


def crawl_page(browser_type_str: str, url: str):
    redirected_urls: dict = {}

    def redirect_handler(response):
        status = response.status
        if 300 <= status <= 399:
            redirected_urls[response.url] = response.headers["location"]
            print(
                f"[Redirect] {response.url} => {response.headers['location']}",
                file=sys.stderr,
            )

    with sync_playwright() as p:
        browser_type = p.chromium
        if browser_type_str == "firefox":
            browser_type = p.firefox
        elif browser_type_str == "webkit":
            browser_type = p.webkit
        browser = browser_type.launch(headless=True)  # デフォルトでsandboxが有効
        page = browser.new_page()
        page.on(
            "response",
            redirect_handler,
        )
        page.goto(url)  # ページ読み込みが完了するまで待機

        # ページ内のコンテンツを取得
        content = page.content()

        # ページ内のリンクリストを取得
        sub_links = page.evaluate(
            """() => {
            return Array.from(document.querySelectorAll('a'))
                .map(link => link.href);
        }"""
        )

        page.close()
        browser.close()
        return content, sub_links, redirected_urls


def crawl_page_in_sandbox(browser_type_str: str, url: str) -> tuple[str, list, dict]:
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
        result = crawl_page(browser_type_str, url)
        return result
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return f"Errro: {e} in {url}", [], {}


def crawl_pages(
    browser_type_str: str,
    urls: set,
    output_root_dir: str,
    target_domains: set = set(),
    processed_urls: set = set(),
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
        for url in urls:
            if url in excluded_urls:
                continue  # excluded_urls に含まれる URL はクロール対象から除外

            try:
                res = pool.apply_async(crawl_page_in_sandbox, (browser_type_str, url))
                results = res.get(timeout=timeout)

                content = results[0]

                for sub_link in results[1]:
                    sub_urls.add(sub_link)

                for key, value in results[2].items():
                    redirected_urls[key] = value

                dirpath = url2dirpath(url)
                makedir("/".join([output_root_dir, browser_type_str, dirpath]))

                # クローリングしたHTMLデータを出力
                output(
                    content,
                    "/".join(
                        [output_root_dir, browser_type_str, dirpath, "content.html"]
                    ),
                )

                # ページ内のリンクリストを出力
                output(
                    sub_urls,
                    "/".join([output_root_dir, browser_type_str, dirpath, "urls.txt"]),
                )

                processed_urls.add(url)  # クロール済みURLは、処理済みURLリストに追加
            except TimeoutError:
                traceback.print_exc()
            except Exception:
                traceback.print_exc()

    # クロール済みリンク、外部リンクは、次のクロール対象(next_urls)から除去する
    next_urls = set()
    links = (urls | sub_urls) - processed_urls - excluded_urls
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
        processed_urls = set()
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
