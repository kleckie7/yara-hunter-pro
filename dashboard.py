import plotly.graph_objects as go
from plotly.subplots import make_subplots
import pandas as pd
import os

def generate_dashboard(results, output_path='reports/yara_hunter_report.html'):
    if not results:
        html = "<h1 style='color:#58a6ff; text-align:center; margin-top:100px;'>No YARA matches found – Clean scan</h1>"
        with open(output_path, 'w') as f:
            f.write(html)
        os.system(f"open '{output_path}'")
        return

    # Clean data for Plotly (convert YARA objects to strings)
    clean_results = []
    for r in results:
        clean = {
            'file': r['file'],
            'rule': r['rule'],
            'size (KB)': round(r['size']/1024, 2),
            'vt_detections': r['vt'].get('detections', 'N/A'),
            'vt_total': r['vt'].get('total', 'N/A')
        }
        clean_results.append(clean)

    df = pd.DataFrame(clean_results)

    fig = make_subplots(
        rows=2, cols=2,
        subplot_titles=('Rule Hits per File', 'File Size Distribution', 'Detailed Results', 'VT Detections'),
        specs=[[{"type": "bar"}, {"type": "histogram"}],
               [{"type": "table", "colspan": 2}, None]]
    )

    # Bar: matches per file
    file_counts = df['file'].value_counts()
    fig.add_trace(go.Bar(x=file_counts.index, y=file_counts.values, marker_color='#58a6ff'), row=1, col=1)

    # Histogram: file sizes
    fig.add_trace(go.Histogram(x=df['size (KB)'], marker_color='#f85149'), row=1, col=2)

    # Table
    fig.add_trace(go.Table(
        header=dict(values=list(df.columns), fill_color='#21262d', font=dict(color='white')),
        cells=dict(values=[df[col] for col in df.columns],
                   fill_color='#161b22',
                   font=dict(color='#e6edf3'))
    ), row=2, col=1)

    fig.update_layout(
        title_text="YARA Hunter Pro – Scan Results",
        title_x=0.5,
        height=900,
        paper_bgcolor='#0d1117',
        plot_bgcolor='#0d1117',
        font=dict(color='#e6edf3')
    )

    os.makedirs("reports", exist_ok=True)
    fig.write_html(output_path)
    os.system(f"open '{output_path}'")
    print(f"Interactive dashboard opened: {output_path}")
