FROM python:3.11-slim
RUN mkdir /app 
COPY /backend /app
COPY pyproject.toml /app 
WORKDIR /app
ENV PYTHONPATH=${PYTHONPATH}:${PWD} 
RUN pip3 install poetry
RUN poetry config virtualenvs.create false
RUN poetry install --no-dev
EXPOSE 8000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0"]