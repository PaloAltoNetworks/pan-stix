class PanStixError(Exception):
    def __init__(self, msg):
        self.msg = msg

    def __str__(self):
        if self.msg is None:
            return ''
        return self.msg
