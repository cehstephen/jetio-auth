# Integration tests (real `jetio`, not the mock)

`tests/conftest.py` replaces `sys.modules["jetio"]` with a `MagicMock()`
and has model classes inherit from plain SQLAlchemy `DeclarativeBase`
rather than Jetio's `JetioModel` -- appropriate for fast, isolated unit
tests of `jetio_auth`'s own logic, but it means those tests never exercise
`JetioModel`'s real `ModelMetaclass` at all.

Anything that depends on the actual integration between a `jetio_auth`
mixin and Jetio's metaclass-driven schema generation needs to run against
the real package instead. This directory holds those tests, kept separate
so they don't inherit `tests/conftest.py`'s module-level mocking (pytest's
conftest scoping is directory-based, so a conftest in `tests/` doesn't
apply here).

Run with:

```
pip install jetio  # the real package, not mocked
pytest tests_integration/
```
