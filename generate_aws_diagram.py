from PIL import Image, ImageDraw, ImageFont
import math
import io
import base64
import re


def generate_aws_diagram(services_text=""):
    """Generate AWS architecture diagram and return as base64 PNG."""

    W, H = 1400, 900
    img = Image.new("RGB", (W, H), "#1a1a2e")
    draw = ImageDraw.Draw(img)

    try:
        font_title = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 26)
        font_label = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 15)
        font_small = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 12)
        font_arrow = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 11)
        font_tiny = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 10)
    except:
        font_title = ImageFont.load_default()
        font_label = font_title
        font_small = font_title
        font_arrow = font_title
        font_tiny = font_title

    CARD = "#16213e"
    BORDER = "#0f3460"
    WHITE = "#ffffff"
    GRAY = "#90a4ae"
    ARROW = "#546e7a"
    LBLBG = "#0d1b2a"

    colors = {
        "user": "#4fc3f7",
        "route53": "#8C4FFF",
        "cf": "#FF9900",
        "s3": "#3F8624",
        "waf": "#DD344C",
        "apigw": "#232F6E",
        "cognito": "#BF0816",
        "lambda": "#FF6600",
        "dynamo": "#6B3FA0",
        "sqs": "#D4AC0D",
        "sns": "#E91E8C",
        "cw": "#00897B",
    }

    def draw_card(x, y, w, h, color, label, sublabel="", icon=""):
        draw.rounded_rectangle([x + 4, y + 4, x + w + 4, y + h + 4], radius=10, fill="#0a0a1a")
        draw.rounded_rectangle([x, y, x + w, y + h], radius=10, fill=CARD, outline=color, width=2)
        draw.rounded_rectangle([x, y, x + w, y + 18], radius=10, fill=color)
        draw.rectangle([x, y + 9, x + w, y + 18], fill=color)
        if icon:
            draw.text((x + w // 2, y + 36), icon, fill=color, font=font_label, anchor="mm")
        draw.text((x + w // 2, y + 55), label, fill=WHITE, font=font_label, anchor="mm")
        if sublabel:
            draw.text((x + w // 2, y + 70), sublabel, fill=GRAY, font=font_tiny, anchor="mm")

    def arrow(x1, y1, x2, y2, label="", color=ARROW, dashed=False):
        if dashed:
            # Draw dashed line
            dist = math.hypot(x2 - x1, y2 - y1)
            steps = int(dist / 12)
            for i in range(steps):
                if i % 2 == 0:
                    t1, t2 = i / steps, (i + 0.5) / steps
                    draw.line([x1 + (x2 - x1) * t1, y1 + (y2 - y1) * t1, x1 + (x2 - x1) * t2, y1 + (y2 - y1) * t2],
                              fill=color, width=1)
        else:
            draw.line([x1, y1, x2, y2], fill=color, width=2)
        ang = math.atan2(y2 - y1, x2 - x1)
        sz = 9
        draw.polygon([(x2, y2), (x2 - sz * math.cos(ang - 0.4), y2 - sz * math.sin(ang - 0.4)),
                      (x2 - sz * math.cos(ang + 0.4), y2 - sz * math.sin(ang + 0.4))], fill=color)
        if label:
            mx, my = (x1 + x2) // 2, (y1 + y2) // 2
            tw = len(label) * 6 + 8
            draw.rounded_rectangle([mx - tw // 2, my - 9, mx + tw // 2, my + 9], radius=3, fill=LBLBG, outline=BORDER)
            draw.text((mx, my), label, fill=GRAY, font=font_arrow, anchor="mm")

    # Title
    draw.text((W // 2, 36), "AWS Serverless Web Application Architecture", fill=WHITE, font=font_title, anchor="mm")
    draw.line([80, 56, W - 80, 56], fill=BORDER, width=1)

    # AWS Region box
    draw.rounded_rectangle([75, 65, W - 75, H - 45], radius=14, outline=BORDER, width=2)
    draw.text((108, 78), "AWS Region: us-east-1", fill=GRAY, font=font_small)

    CW, CH = 118, 88

    nodes = {
        "user": (95, 420, 100, 84),
        "route53": (240, 420, CW, CH),
        "cf": (415, 260, CW, CH),
        "s3": (415, 130, CW, CH),
        "waf": (590, 260, CW, CH),
        "apigw": (765, 260, CW, CH),
        "cognito": (765, 130, CW, CH),
        "lambda": (940, 260, CW, CH),
        "dynamo": (1115, 160, CW, CH),
        "sqs": (1115, 340, CW, CH),
        "sns": (1115, 500, CW, CH),
        "cw": (300, 640, 800, 72),
    }

    def cx(n):
        return nodes[n][0] + nodes[n][2] // 2

    def cy(n):
        return nodes[n][1] + nodes[n][3] // 2

    def L(n):
        return nodes[n][0]

    def R(n):
        return nodes[n][0] + nodes[n][2]

    def T(n):
        return nodes[n][1]

    def B(n):
        return nodes[n][1] + nodes[n][3]

    # Arrows
    arrow(R("user"), cy("user"), L("route53"), cy("route53"), "HTTPS")
    arrow(R("route53"), cy("route53"), L("cf"), cy("cf"), "Routes Traffic")
    arrow(cx("cf"), T("cf"), cx("s3"), B("s3"), "Static Assets")
    arrow(R("cf"), cy("cf"), L("waf"), cy("waf"), "Forward")
    arrow(R("waf"), cy("waf"), L("apigw"), cy("apigw"), "Filtered Req")
    arrow(cx("apigw"), T("apigw"), cx("cognito"), B("cognito"), "Validate JWT")
    arrow(R("apigw"), cy("apigw"), L("lambda"), cy("lambda"), "Invoke")
    arrow(R("lambda"), cy("lambda") - 18, L("dynamo"), cy("dynamo"), "Read/Write")
    arrow(R("lambda"), cy("lambda") + 18, L("sqs"), cy("sqs"), "Queue Task")
    arrow(cx("sqs"), B("sqs"), cx("sns"), T("sns"), "Trigger")
    # CloudWatch dashed arrows
    arrow(cx("cw"), T("cw"), cx("lambda"), B("lambda"), "Logs", "#00897B", dashed=True)
    arrow(L("cw") + 60, T("cw"), cx("apigw"), B("apigw"), "", "#00897B", dashed=True)

    # Cards
    x, y, w, h = nodes["user"]
    draw.rounded_rectangle([x + 4, y + 4, x + w + 4, y + h + 4], radius=10, fill="#0a0a1a")
    draw.rounded_rectangle([x, y, x + w, y + h], radius=10, fill="#1e3a5f", outline=colors["user"], width=2)
    draw.text((x + w // 2, y + 28), "👤", fill=colors["user"], font=font_label, anchor="mm")
    draw.text((x + w // 2, y + 52), "User", fill=WHITE, font=font_label, anchor="mm")
    draw.text((x + w // 2, y + 67), "Browser", fill=GRAY, font=font_tiny, anchor="mm")

    draw_card(*nodes["route53"], colors["route53"], "Route 53", "DNS", "🌐")
    draw_card(*nodes["cf"], colors["cf"], "CloudFront", "CDN", "🚀")
    draw_card(*nodes["s3"], colors["s3"], "Amazon S3", "Storage", "🪣")
    draw_card(*nodes["waf"], colors["waf"], "AWS WAF", "Firewall", "🛡")
    draw_card(*nodes["apigw"], colors["apigw"], "API Gateway", "REST API", "🔗")
    draw_card(*nodes["cognito"], colors["cognito"], "Cognito", "Auth", "🔐")
    draw_card(*nodes["lambda"], colors["lambda"], "Lambda", "Serverless", "λ")
    draw_card(*nodes["dynamo"], colors["dynamo"], "DynamoDB", "NoSQL DB", "🗄")
    draw_card(*nodes["sqs"], colors["sqs"], "Amazon SQS", "Queue", "📨")
    draw_card(*nodes["sns"], colors["sns"], "Amazon SNS", "Notify", "🔔")

    # CloudWatch wide bar
    x, y, w, h = nodes["cw"]
    draw.rounded_rectangle([x + 4, y + 4, x + w + 4, y + h + 4], radius=10, fill="#0a0a1a")
    draw.rounded_rectangle([x, y, x + w, y + h], radius=10, fill=CARD, outline=colors["cw"], width=2)
    draw.rounded_rectangle([x, y, x + w, y + 18], radius=10, fill=colors["cw"])
    draw.rectangle([x, y + 9, x + w, y + 18], fill=colors["cw"])
    draw.text((x + w // 2, y + 40), "📊  Amazon CloudWatch — Monitoring & Logging (All Services)", fill=WHITE,
              font=font_label, anchor="mm")

    # Legend
    lx, ly = 90, H - 35
    legend = [("■", colors["route53"], "DNS"), ("■", colors["cf"], "CDN"), ("■", colors["s3"], "Storage"),
              ("■", colors["waf"], "Firewall"), ("■", colors["apigw"], "API"), ("■", colors["lambda"], "Compute"),
              ("■", colors["dynamo"], "Database"), ("■", colors["sqs"], "Queue"), ("■", colors["sns"], "Notify"),
              ("■", colors["cw"], "Monitor")]
    for i, (sym, col, lbl) in enumerate(legend):
        ox = lx + i * 130
        draw.text((ox, ly), sym, fill=col, font=font_small)
        draw.text((ox + 14, ly), lbl, fill=GRAY, font=font_small)

    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return base64.b64encode(buf.read()).decode("utf-8")


if __name__ == "__main__":
    b64 = generate_aws_diagram()
    # save test
    import base64

    with open("/mnt/user-data/outputs/aws_diagram_v2.png", "wb") as f:
        f.write(base64.b64decode(b64))
    print("Done!")