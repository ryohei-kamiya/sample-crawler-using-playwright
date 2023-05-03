# sample-crawler-using-playwright

## Usage
```
docker-compose up -d
docker exec -it sample-crawler-using-playwright /home/crawler/.venv/bin/python main.py /home/crawler/test/test-urls.txt --depth 0 --limit 2 --browsers chromium firefox webkit
```
