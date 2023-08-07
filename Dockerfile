FROM python:3.10-alpine3.18

ADD main.py .

RUN pip3 install requests

CMD [ "python3", "main.py" ]