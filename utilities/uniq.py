import itertools

def assert_iterable(iterable):
    try:
        iterable.__iter__()
    except AttributeError:
        raise ArgumentError("Input must be iterable")

def uniq(iterable):
    assert_iterable(iterable)
    if type(iterable) is dict:
        vals = [v for _, v in iterable.items()]
        groups = [k for k, _ in itertools.groupby(sorted(vals))]
        groups = [(i+1, v) for i, v in enumerate(groups)]
        return dict(groups)
    return [k for k, _ in itertools.groupby(sorted(iterable))]
