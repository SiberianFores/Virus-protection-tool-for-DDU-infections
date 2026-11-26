"""生成应用图标 assets/app.ico"""
from PIL import Image, ImageDraw
import os

OUT = os.path.join(os.path.dirname(__file__), "assets")
os.makedirs(OUT, exist_ok=True)


def rounded(draw, box, r, fill):
    draw.rounded_rectangle(box, radius=r, fill=fill)


def shield(size=256):
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    s = size / 256.0

    def P(x, y):
        return (x * s, y * s)

    # 外圈盾牌
    body = [
        P(128, 14), P(230, 50), P(230, 132),
        P(226, 170), P(198, 208), P(128, 242),
        P(58, 208), P(30, 170), P(26, 132), P(26, 50),
    ]
    d.polygon(body, fill=(18, 26, 38, 255))
    d.line(body + [body[0]], fill=(47, 129, 247, 255), width=int(10 * s), joint="curve")

    # 内层高光
    inner = [
        P(128, 40), P(206, 68), P(206, 132),
        P(202, 162), P(180, 192), P(128, 218),
        P(76, 192), P(54, 162), P(50, 132), P(50, 68),
    ]
    d.polygon(inner, fill=(22, 34, 52, 255))

    # 对勾
    d.line([P(84, 130), P(116, 164), P(176, 96)],
           fill=(63, 185, 80, 255), width=int(16 * s), joint="curve")
    # 危险点（提示“查杀”）
    d.ellipse([P(150, 148), P(186, 184)], fill=(248, 81, 73, 255))
    d.line([P(160, 158), P(176, 174)], fill=(255, 255, 255, 255), width=int(7 * s))
    d.line([P(176, 158), P(160, 174)], fill=(255, 255, 255, 255), width=int(7 * s))
    return img


base = shield(256)
sizes = [(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)]
base.save(os.path.join(OUT, "app.ico"), format="ICO", sizes=sizes)
base.save(os.path.join(OUT, "app.png"))
print("icon written", os.path.join(OUT, "app.ico"))
