#!/usr/bin/env python3
# file: dir_status_size.py

import requests
from typing import List, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
import random
import sys

def load_paths(file_path: str) -> List[str]:
    """
    Загружает список путей (директорий/файлов) из файла, по одному на строке.
    :param file_path: путь к файлу со списком
    :return: список непустых строк
    """
    with open(file_path, 'r', encoding='utf-8') as f:
        return [line.strip() for line in f if line.strip()]

def probe_url(domain: str, path: str,
              min_delay: float = 0.1,
              max_delay: float = 0.3) -> Tuple[str, int, int]:
    """
    Проверяет URL и возвращает (полный_URL, status_code, size_bytes).
    Сначала HEAD, если нет Content-Length — GET и считаем len(content).
    Добавляет случайную задержку.
    """
    url = domain.rstrip('/') + '/' + path.lstrip('/')
    try:
        # пробуем HEAD
        r = requests.head(url, timeout=10, allow_redirects=True)
        status = r.status_code
        if 'Content-Length' in r.headers:
            size = int(r.headers['Content-Length'])
        else:
            # fallback — полный GET
            r = requests.get(url, timeout=10)
            status = r.status_code
            size = len(r.content)
    except requests.RequestException as e:
        # в случае ошибки считаем, что ответ «0» и размер «0»
        status = getattr(e.response, 'status_code', 0) if hasattr(e, 'response') else 0
        size = 0

    # чтобы не бить слишком часто
    time.sleep(random.uniform(min_delay, max_delay))
    return url, status, size

def main(domain: str, paths_file: str, max_workers: int = 10):
    paths = load_paths(paths_file)
    results = []

    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(probe_url, domain, p): p for p in paths}
        for fut in as_completed(futures):
            url, status, size = fut.result()
            results.append((url, status, size))
            print(f"{status:3d}  {size:7d} bytes  {url}")

    # если нужно, можно отсортировать или сохранить в CSV:
    # results.sort(key=lambda x: x[1])  

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python3 dir_status_size.py <domain> <paths_file> [max_workers]")
        sys.exit(1)

    domain = sys.argv[1]
    paths_file = sys.argv[2]
    workers = int(sys.argv[3]) if len(sys.argv) > 3 else 10

    main(domain, paths_file, workers)
