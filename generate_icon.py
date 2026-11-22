"""Generate a gamer-themed cyber shield icon for LootCheck."""

import os
from PIL import Image, ImageDraw


def create_shield_icon():
    sizes = [(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)]
    images = []

    for width, height in sizes:
        img = Image.new("RGBA", (width, height), (0, 0, 0, 0))
        draw = ImageDraw.Draw(img)

        # Scale parameters
        w, h = width, height
        pad = max(1, w // 16)

        # Draw dark shield polygon
        # Points: Top-left, Top-right, Mid-right, Bottom-tip, Mid-left
        p_top_l = (pad, pad + h // 8)
        p_top_mid = (w // 2, pad)
        p_top_r = (w - pad - 1, pad + h // 8)
        p_mid_r = (w - pad - 1, int(h * 0.6))
        p_bottom = (w // 2, h - pad - 1)
        p_mid_l = (pad, int(h * 0.6))

        points = [p_top_l, p_top_mid, p_top_r, p_mid_r, p_bottom, p_mid_l]

        # Dark shield body (#16213E)
        draw.polygon(points, fill=(22, 33, 62, 255))

        # Neon green border (#00FF88)
        border_width = max(1, w // 24)
        draw.polygon(points, outline=(0, 255, 136, 255), width=border_width)

        # Inner crosshair or checkmark
        # Draw a stylish gaming cross / checkmark in neon green
        if w >= 32:
            inner_points = [
                (w // 2, int(h * 0.25)),
                (int(w * 0.72), int(h * 0.35)),
                (int(w * 0.72), int(h * 0.58)),
                (w // 2, int(h * 0.78)),
                (int(w * 0.28), int(h * 0.58)),
                (int(w * 0.28), int(h * 0.35)),
            ]
            draw.polygon(inner_points, fill=(10, 42, 26, 200), outline=(0, 255, 136, 180), width=1)

            # Center checkmark symbol
            chk_start = (int(w * 0.36), int(h * 0.48))
            chk_mid = (int(w * 0.46), int(h * 0.60))
            chk_end = (int(w * 0.65), int(h * 0.38))
            chk_width = max(1, w // 20)
            draw.line([chk_start, chk_mid, chk_end], fill=(0, 255, 136, 255), width=chk_width)
        else:
            # Minimal center dot/plus for tiny sizes
            draw.line([(w // 2, int(h * 0.3)), (w // 2, int(h * 0.7))], fill=(0, 255, 136, 255), width=1)
            draw.line([(int(w * 0.3), h // 2), (int(w * 0.7), h // 2)], fill=(0, 255, 136, 255), width=1)

        images.append(img)

    base_dir = os.path.dirname(os.path.abspath(__file__))
    assets_dir = os.path.join(base_dir, "assets")
    images_dir = os.path.join(assets_dir, "images")
    os.makedirs(images_dir, exist_ok=True)

    ico_path = os.path.join(assets_dir, "icon.ico")
    png_path = os.path.join(images_dir, "logo.png")

    images[0].save(
        ico_path,
        format="ICO",
        sizes=sizes,
        append_images=images[1:]
    )
    # Also save PNG preview
    images[-1].save(png_path, format="PNG")
    print(f"Generated {ico_path} with {len(sizes)} resolutions and {png_path}")


if __name__ == "__main__":
    create_shield_icon()
