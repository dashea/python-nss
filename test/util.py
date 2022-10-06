import shutil


def resolve_path(program: str) -> str:
    prog_path = shutil.which(program)
    if prog_path is None:
        raise RuntimeError("%s not found" % program)
    return prog_path
