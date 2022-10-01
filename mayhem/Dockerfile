# Build Stage
FROM fuzzers/atheris:2.0.7-python3.9

ADD ./mayhem/fuzz_bvv.py /fuzz_bvv.py
RUN pip install claripy

CMD ["/fuzz_bvv.py"]
