from __future__ import annotations

import argparse
import asyncio
import base64
import html
import json
import sys
from pathlib import Path

import cv2

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app import __version__
from app.analyzer import analyze_payload
from app.decoder import decode_qr

OUT = ROOT / "build" / "controlled_qr_test"

CANARY = "REDACTION-CANARY-92"
PAYLOAD = (
    "https://singpass-login.example/verify?"
    "redirect=https%3A%2F%2Fevil.example%2Flogin%3Ftoken%3D"
    + CANARY
    + "&urgent=verify-account"
)


def esc(value) -> str:
    return html.escape(str(value if value is not None else ""))


async def main(output_dir: Path = OUT) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    encoder = cv2.QRCodeEncoder_create()
    matrix = encoder.encode(PAYLOAD)
    qr_path = output_dir / "controlled_phishing_qr.png"
    if not cv2.imwrite(str(qr_path), matrix):
        raise RuntimeError("Could not write QR evidence image")

    payloads, image_hash, image_evidence = decode_qr(qr_path.read_bytes())
    result = await analyze_payload(payloads[0], image_hash, False, image_evidence)
    report = result.to_dict()
    report["controlled_test"] = {
        "scenario": "Singapore government-service brand impersonation with a nested credential destination",
        "network_activity": "None; direct destination preflight disabled",
        "expected": "Dangerous verdict, brand/nested destination findings, and secret redaction",
        "secret_canary_absent_from_serialized_result": CANARY not in json.dumps(report),
    }
    serialized = json.dumps(report, indent=2, ensure_ascii=False)
    if CANARY in serialized:
        raise AssertionError("Privacy failure: secret canary remained in report data")
    json_path = output_dir / "NexVision_QR_Shield_Controlled_Test_Report.json"
    json_path.write_text(serialized + "\n", encoding="utf-8")

    risk_groups = report["engine"].get("risk_groups", {})
    group_rows = "".join(
        f"<tr><td>{esc(name.title())}</td><td>{int(value)}</td></tr>"
        for name, value in risk_groups.items()
    )
    finding_rows = "".join(
        f"<tr><td><span class='sev {esc(item['severity'])}'>{esc(item['severity'])}</span></td>"
        f"<td><strong>{esc(item['title'])}</strong><br><small>{esc(item['code'])}</small></td>"
        f"<td>{esc(item['detail'])}</td><td>{int(item['score'])}</td></tr>"
        for item in report["findings"]
    )
    graph = report.get("decoded_details", {}).get("destination_graph", [])
    graph_rows = "".join(
        f"<tr><td>{esc(node['id'])}</td><td>{esc(node['parent'] or 'root')}</td><td>{esc(node['depth'])}</td>"
        f"<td>{esc(node['hostname'])}</td><td class='mono'>{esc(node['url'])}</td></tr>"
        for node in graph
    ) or "<tr><td colspan='5'>No nested destination graph produced.</td></tr>"
    qr_b64 = base64.b64encode(qr_path.read_bytes()).decode("ascii")
    report_html = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>NexVision QR Shield — Controlled Test Report</title>
<style>
:root{{--ink:#17211f;--muted:#66736f;--line:#d8e0dd;--green:#087a59;--red:#b4232f;--amber:#a56600;--bg:#f4f7f6}}
*{{box-sizing:border-box}} body{{margin:0;background:var(--bg);color:var(--ink);font:14px/1.55 system-ui,-apple-system,"Segoe UI",sans-serif}}
.page{{max-width:1100px;margin:30px auto;background:white;border:1px solid var(--line);box-shadow:0 12px 35px #1c2b2620}}
header{{padding:32px 40px;background:#071511;color:white;display:flex;justify-content:space-between;align-items:end}}
header h1{{margin:4px 0 0;font-size:28px}} header p{{margin:0;color:#a9bcb5}} .brand{{color:#52e3b1;font-weight:800;letter-spacing:.14em;font-size:11px}}
.verdict{{padding:24px 40px;background:#fff3f4;border-bottom:1px solid #f2c9ce;display:flex;align-items:center;justify-content:space-between}}
.verdict h2{{color:var(--red);margin:0;font-size:28px}} .score{{width:82px;height:82px;border:7px solid var(--red);border-radius:50%;display:grid;place-items:center;font-size:25px;font-weight:900;color:var(--red)}}
main{{padding:30px 40px}} h3{{margin:28px 0 10px;font-size:17px}} .grid{{display:grid;grid-template-columns:1fr 1fr;gap:14px}}
.card{{border:1px solid var(--line);border-radius:10px;padding:16px}} .card span{{font-size:10px;color:var(--muted);letter-spacing:.1em;text-transform:uppercase}}
.card b{{display:block;margin-top:5px;overflow-wrap:anywhere}} .evidence{{display:grid;grid-template-columns:220px 1fr;gap:22px;align-items:center}}
.evidence img{{width:210px;image-rendering:pixelated;border:14px solid white;box-shadow:0 0 0 1px var(--line)}}
.mono{{font:11px/1.45 ui-monospace,SFMono-Regular,Consolas,monospace;word-break:break-all}} table{{width:100%;border-collapse:collapse}}
th,td{{padding:10px;border:1px solid var(--line);text-align:left;vertical-align:top}} th{{background:#edf3f1;font-size:11px;text-transform:uppercase;letter-spacing:.05em}}
.sev{{font-size:9px;text-transform:uppercase;font-weight:800}} .critical,.high{{color:var(--red)}} .medium,.low{{color:var(--amber)}} .info{{color:var(--green)}}
.pass{{color:var(--green);font-weight:800}} .notice{{padding:14px;border-left:4px solid var(--green);background:#effaf6}} footer{{padding:20px 40px;border-top:1px solid var(--line);color:var(--muted);font-size:11px}}
@media print{{body{{background:white}}.page{{margin:0;border:0;box-shadow:none}}}} @media(max-width:700px){{.grid,.evidence{{grid-template-columns:1fr}}header{{align-items:start;gap:16px;flex-direction:column}}}}
</style></head><body><div class="page">
<header><div><div class="brand">NEXVISION OSINT360</div><h1>QR Shield Controlled Test Report</h1></div><p>Engine v{esc(report['engine']['version'])}<br>{esc(report['analyzed_at'])}</p></header>
<section class="verdict"><div><small>FINAL ASSESSMENT</small><h2>{esc(report['verdict'])}</h2><p>Explainable risk index — not a probability</p></div><div class="score">{int(report['score'])}</div></section>
<main>
<div class="notice">✓ Controlled test completed entirely offline. No destination or professional reputation API was contacted.</div>
<h3>Test evidence</h3><div class="evidence"><img src="data:image/png;base64,{qr_b64}" alt="Controlled phishing QR evidence">
<div class="grid"><div class="card"><span>Scenario</span><b>{esc(report['controlled_test']['scenario'])}</b></div><div class="card"><span>Network activity</span><b>{esc(report['controlled_test']['network_activity'])}</b></div><div class="card"><span>Image SHA-256</span><b class="mono">{esc(report['sha256'])}</b></div><div class="card"><span>Payload SHA-256</span><b class="mono">{esc(report['payload_sha256'])}</b></div><div class="card"><span>Result integrity SHA-256</span><b class="mono">{esc(report['evidence_integrity']['canonical_result_sha256'])}</b></div><div class="card"><span>Decoder</span><b>{esc(report['image_analysis']['decoder_consensus'])}</b></div><div class="card"><span>Secret handling</span><b class="pass">PASS — canary absent from report data</b></div></div></div>
<h3>Privacy-safe decoded payload</h3><div class="card mono">{esc(report['payload'])}</div>
<h3>Destination identity</h3><div class="grid"><div class="card"><span>Displayed hostname</span><b>{esc(report['display_host'])}</b></div><div class="card"><span>Controlling registrable domain</span><b>{esc(report['decoded_details'].get('registrable_domain'))}</b></div></div>
<h3>Destination graph</h3><table><thead><tr><th>ID</th><th>Parent</th><th>Depth</th><th>Hostname</th><th>Privacy-safe URL</th></tr></thead><tbody>{graph_rows}</tbody></table>
<h3>Risk-group contributions</h3><table><thead><tr><th>Evidence group</th><th>Points</th></tr></thead><tbody>{group_rows}</tbody></table>
<h3>Explainable findings</h3><table><thead><tr><th>Severity</th><th>Finding</th><th>Explanation</th><th>Points</th></tr></thead><tbody>{finding_rows}</tbody></table>
<h3>Important limitations</h3><ul>{''.join(f'<li>{esc(item)}</li>' for item in report['limitations'])}</ul>
</main><footer>Generated by NexVision QR Shield v{esc(__version__)} · Controlled test evidence · No external API used</footer>
</div></body></html>"""
    html_path = output_dir / "NexVision_QR_Shield_Controlled_Test_Report.html"
    html_path.write_text(report_html, encoding="utf-8")
    print(json.dumps({
        "html": str(html_path), "json": str(json_path), "qr": str(qr_path),
        "verdict": report["verdict"], "score": report["score"],
        "findings": len(report["findings"]), "secret_redaction": report["controlled_test"]["secret_canary_absent_from_serialized_result"],
    }))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate a fully offline controlled QR Shield test report.")
    parser.add_argument("--output-dir", type=Path, default=OUT)
    arguments = parser.parse_args()
    asyncio.run(main(arguments.output_dir))
