# 使用官方的Python镜像作为基础镜像
FROM python:3.11
WORKDIR /app

COPY . .

RUN useradd -m checker \
    && chown -R checker:checker /app
USER checker

RUN pip install --user --no-cache-dir -r requirements.txt

ENV PATH="/home/checker/.local/bin:${PATH}"

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "6900"]
