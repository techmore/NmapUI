class LazyObjectProxy:
    def __init__(self, getter):
        object.__setattr__(self, "_getter", getter)

    def _get_target(self):
        return object.__getattribute__(self, "_getter")()

    def __getattr__(self, name):
        return getattr(self._get_target(), name)

    def __setattr__(self, name, value):
        setattr(self._get_target(), name, value)

    def __call__(self, *args, **kwargs):
        return self._get_target()(*args, **kwargs)

    def __repr__(self):
        return repr(self._get_target())
