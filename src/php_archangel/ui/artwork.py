"""Cross-terminal artwork: truecolor half-block image or optional inline splash."""
from __future__ import annotations
import base64
import io
import os
from pathlib import Path
import shutil
import sys
from PIL import Image, ImageOps
from rich.text import Text

ASSET = Path(__file__).parent / 'assets' / 'archangel_original.png'

def pixel_art(width: int = 49, height: int = 17, path: Path = ASSET) -> Text:
    """Contain-and-center render: full figure, no cropping, dark padding."""
    width, height = max(8, min(width, 170)), max(4, min(height, 44))
    im = Image.open(path)
    im2 = im.convert('RGB')
    im.close()
    im2 = ImageOps.contain(im2, (width, height * 2), Image.Resampling.LANCZOS)
    canvas = Image.new('RGB', (width, height * 2), '#020813')
    canvas.paste(im2, ((width - im2.width) // 2,
                       (height * 2 - im2.height) // 2))   # centered both axes
    result = Text(no_wrap=True, overflow='crop')
    for y in range(height):
        for x in range(width):
            top = canvas.getpixel((x, y * 2))
            bottom = canvas.getpixel((x, y * 2 + 1))
            result.append('▀', style=f'rgb({top[0]},{top[1]},{top[2]}) '
                                      f'on rgb({bottom[0]},{bottom[1]},{bottom[2]})')
        if y < height - 1:
            result.append('\n')
    return result


def detect_protocol() -> str | None:
    """Conservative detection; override explicitly if your terminal supports more."""
    if not sys.stdout.isatty(): return None
    if os.environ.get('KITTY_WINDOW_ID') or os.environ.get('TERM', '').startswith('xterm-kitty'):
        return 'kitty'
    if os.environ.get('TERM_PROGRAM') in {'iTerm.app', 'WezTerm'}:
        return 'iterm'
    return None

def inline_splash(protocol: str = 'auto', path: Path = ASSET, width_cells: int = 70) -> bool:
    """Print true image *before* Rich starts drawing. Not for Rich Live panels.

    Kitty: graphics transmission with placement; iTerm2: inline file escape.
    """
    if not sys.stdout.isatty(): return False
    protocol = detect_protocol() if protocol == 'auto' else protocol
    if protocol not in {'kitty', 'iterm'}: return False
    with Image.open(path) as src:
        im = src.convert('RGB')
        im.thumbnail((950, 950))
        buf = io.BytesIO(); im.save(buf, format='PNG', optimize=True)
    encoded = base64.b64encode(buf.getvalue()).decode('ascii')
    if protocol == 'iterm':
        sys.stdout.write(f'\033]1337;File=inline=1;width={width_cells};preserveAspectRatio=1:{encoded}\a\n')
    else:
        # Kitty graphics protocol chunks are limited in size. Use a unique image id.
        # f=100 PNG, a=T transmit/display, c requested columns; m=1 more chunks.
        chunk_size = 4096
        for index in range(0, len(encoded), chunk_size):
            part = encoded[index:index+chunk_size]
            more = int(index+chunk_size < len(encoded))
            params = f'f=100,a=T,i=7321,c={width_cells},m={more}' if index == 0 else f'm={more}'
            sys.stdout.write(f'\033_G{params};{part}\033\\')
        sys.stdout.write('\n')
    sys.stdout.flush()
    return True
