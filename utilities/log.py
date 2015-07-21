# Object to transparently handle optional logging
# Set logger to default to NoneLogger(), and call methods w/o None checks


class NoneLogger:

    def log(*args):
        pass

    def debug(*args):
        pass

    def info(*args):
        pass

    def warning(*args):
        pass

    def error(*args):
        pass

    def critical(*args):
        pass
