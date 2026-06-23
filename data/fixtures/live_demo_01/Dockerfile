FROM python:3.11-slim
WORKDIR /app
COPY source/app.py /app/app.py
RUN echo 'flag{live_lfi_demo_ok}' > /flag.txt
EXPOSE 8080
CMD ["python", "/app/app.py"]
