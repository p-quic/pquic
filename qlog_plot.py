import json
import sys

import matplotlib.pyplot as plt

if len(sys.argv) < 3:
    print('Usage: %s trace_file metric_reference..' % sys.argv[0])
    print('Example: %s server.qlog.json CWIN_UPDATE.cwin ACK_FRAME_PARSED.largest' % sys.argv[0])
    exit(-1)

trace_filename = sys.argv[1]

with open(trace_filename) as f:
    qlog = json.load(f)

t = qlog['traces'][0]

metrics_data = []
for metric_ref in sys.argv[2:]:
    metric_type, attribute = metric_ref.split('.')
    x = []
    y = []
    for timestamp, _, ev_type, _, _, data in t['events']:
        if ev_type == metric_type:
            x.append(timestamp/(1000 if t['configuration']['time_units'] == 'us' else 1))
            y.append(data[attribute])

    metrics_data.append((x, y, metric_ref))

fig, ax1 = plt.subplots()
ax2 = plt.twinx()

legends = []
for (x, y, _), ax, c in zip(metrics_data, [ax1, ax2], ['red', 'green']):
    l, = ax.plot(x, y, color=c, marker='.')
    ax.set_xlabel('ms')
    legends.append(l)

plt.xlabel('ms')
plt.legend(legends, [ref for _, _, ref in metrics_data])
plt.show()
