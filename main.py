import argparse
import re
import asyncio
import traceback
import random
import os
from typing import Any
from urllib.parse import urlparse
from playwright.async_api import async_playwright
from playwright.async_api import BrowserType


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
        elif type(data) == list:
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


async def crawl_pages(
    browser_type: BrowserType,
    urls: set[str],
    output_root_dir: str,
    target_domains: set = set(),
    processed_urls: set = set(),
    excluded_urls: set = set(),
    redirected_urls: dict = {},
    depth: int = -1,
    limit: int = 5,  # 同時にクロールするURLは5つまで
):
    if not bool(urls):  # クロール対象URLリスト(urls)が空の場合は処理を中断
        return

    sem = asyncio.Semaphore(limit)

    async def crawl_page(url: str, output_root_dir: str, sub_urls: set = set()):
        if url in excluded_urls:  # excluded_urls に含まれるURLはクロール対象から除外
            return

        async def redirect_handler(response):
            status = response.status
            if 300 <= status <= 399:
                redirected_urls[response.url] = response.headers["location"]
                print(
                    f"[Detected redirect]{response.url} -> {response.headers['location']}"
                )

        async with sem:
            try:
                browser = await browser_type.launch(headless=True)
                page = await browser.new_page()
                page.on(
                    "response",
                    lambda response: asyncio.ensure_future(redirect_handler(response)),
                )
                await page.goto(url)  # ページ読み込みが完了するまで待機

                # ページ内のコンテンツを取得
                content = await page.content()

                # ページ内のリンクリストを取得
                sub_links = await page.evaluate(
                    """() => {
                    return Array.from(document.querySelectorAll('a'))
                        .map(link => link.href);
                }"""
                )
                for sub_link in sub_links:
                    sub_urls.add(sub_link)

                await page.close()
                await browser.close()

                dirpath = url2dirpath(url)
                makedir("/".join([output_root_dir, browser_type.name, dirpath]))

                # クローリングしたHTMLデータを出力
                output(
                    content,
                    "/".join(
                        [output_root_dir, browser_type.name, dirpath, "content.html"]
                    ),
                )

                # ページ内のリンクリストを出力
                output(
                    content,
                    "/".join([output_root_dir, browser_type.name, dirpath, "urls.txt"]),
                )

                processed_urls.add(url)  # クロール済みURLは、処理済みURLリストに追加
            except Exception:
                traceback.print_exc()

    sub_urls = set()
    randomized_urls = list(urls)
    random.shuffle(randomized_urls)
    tasks = [crawl_page(url, output_root_dir, sub_urls) for url in randomized_urls]
    await asyncio.gather(*tasks)

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
        await crawl_pages(
            browser_type,
            next_urls,
            output_root_dir,
            target_domains,
            processed_urls,
            excluded_urls,
            redirected_urls,
            depth - 1,
            limit,
        )


async def main(args):
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

    processed_urls = set()
    excluded_urls = set()
    redirected_urls = {}
    for browser_type_str in args.browsers:
        async with async_playwright() as p:
            browser_type = p.chromium
            if browser_type_str == "firefox":
                browser_type = p.firefox
            elif browser_type_str == "webkit":
                browser_type = p.webkit
            await crawl_pages(
                browser_type,
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
        default="output",
        help="Set output root directory",
    )
    parser.add_argument(
        "--depth", type=int, default=-1, help="Set the maximum number of sublinks"
    )
    parser.add_argument(
        "--limit", type=int, default=-1, help="Set the concurrent crawl executions"
    )
    args = parser.parse_args()
    asyncio.run(main(args))
