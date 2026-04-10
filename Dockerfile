FROM python:3.11-alpine
LABEL maintainer="lorenz.vanthillo@gmail.com"
COPY . /app
WORKDIR /app
RUN pip install -r requirements.txt \
    && cp config/ui_config.example.json config/ui_config.json
EXPOSE 8080
ENTRYPOINT ["python"]
CMD ["src/app.py"]
