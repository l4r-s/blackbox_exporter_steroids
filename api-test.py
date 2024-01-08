import asyncio
import httpx
import sys
import argparse
import logging
import time
import json

logging.basicConfig(level=logging.ERROR, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

async def fetch(url, client, duration, token, delay, data, logger):
    """Asynchronous function to make HTTP requests in a loop for a given duration."""
    start_time = time.time()
    headers = {}
    if token:
        headers = { "Authorization": token }

    while time.time() - start_time < duration:
        try:
            response = await client.post(url, headers=headers, json=data)
        except Exception as e:
            logger.exception(f"An error occurred during the HTTP request: {e}")


        await asyncio.sleep(delay)

async def main(duration, worker, url, token, delay, data, timeout_connect, timeout_read, timeout_write, logger):
    urls = [url] * worker
    timeout = httpx.Timeout(
        connect=timeout_connect,
        read=timeout_read,
        write=timeout_write,
        pool=None
    )
    async with httpx.AsyncClient(timeout=timeout) as client:
        tasks = [fetch(url, client, duration, token, delay, data, logger) for url in urls]
        await asyncio.gather(*tasks)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Pinginator worker API Test')

    # Adding arguments
    parser.add_argument('url', type=str, help='URL to call')
    parser.add_argument('body', type=str, help='Request body to call')
    parser.add_argument('--token', type=str, help='Auth token, if omited none wil be sended')
    parser.add_argument('--worker', type=int, help='Number of workers (default 10)')
    parser.add_argument('--delay', type=float, help='Delay between each call (per worker, default 0.1)')
    parser.add_argument('--duration', type=float, help='Duration, in seconds (Default 60)')

    parser.add_argument('--timeout', type=float, help='Global timeout for read, write and connect. Overwrites the others if set (Default 10)')
    parser.add_argument('--timeout-read', type=float, help='Timeout for read (Default 10)')
    parser.add_argument('--timeout-write', type=float, help='Timeout for write (Default 10)')
    parser.add_argument('--timeout-connect', type=float, help='Timeout for connect (Default 10)')


    # Parsing arguments
    args = parser.parse_args()

    url = args.url
    body = args.body
    token = args.token

    data = json.loads(body)


    timeout_read = args.timeout_read
    timeout_write = args.timeout_write
    timeout_connect = args.timeout_connect

    if args.timeout:
        timeout_read = args.timeout
        timeout_write = args.timeout
        timeout_connect = args.timeout

    if not timeout_read:
        timeout_read = 10
    if not timeout_write:
        timeout_write = 10
    if not timeout_connect:
        timeout_connect = 10

    worker = args.worker
    if not worker:
        worker = 10

    delay = args.delay
    if not delay:
        delay = 0.1

    duration = args.duration
    if not duration:
        duration = 60

    logger.info(f"Starting test on url: {url}, with token: {token}, worker: {worker}, delay: {delay}, duration: {duration}")
    asyncio.run(
        main(
            duration=duration,
            worker=worker,
            url=url,
            token=token,
            delay=delay,
            data=data,
            timeout_connect=timeout_connect,
            timeout_read=timeout_read,
            timeout_write=timeout_write,
            logger=logger,
        )
    )

