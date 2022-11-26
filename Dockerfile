FROM python:3.11
WORKDIR /code

COPY ./app/requirements.txt /code/requirements.txt
RUN pip install -r requirements.txt

RUN set PYTHONPATH=.
COPY ./app/main.py /code

EXPOSE 20153
ENTRYPOINT ["uvicorn"]
CMD ["main:app", "--host", "0.0.0.0", "--port", "20153"]