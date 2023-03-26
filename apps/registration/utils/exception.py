def get_first_exception_message(ex):
    for err in ex.detail.items():
        return err[1][0]