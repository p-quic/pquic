import json
import sys

import matplotlib.pyplot as plt

if len(sys.argv) < 3:
    print('Usage: %s trace_file metric_reference..' % sys.argv[0])
    print('Example: %s server.qlog.json CWIN_UPDATE.cwin[cc_path],BYTES_IN_TRANSIT_UPDATE.bytes_in_transit[path]' % sys.argv[0])
    exit(-1)

trace_filename = sys.argv[1]

with open(trace_filename) as f:
    qlog = json.load(f)

t = qlog['traces'][0]

timestamps = {}
for e in t['events']:
    timestamps[e[0]] = e

metrics_data = []
for metric_ref in sys.argv[2:]:
    metric_type, attribute = metric_ref.split('.')
    context = None
    if '[' in attribute and ']' in attribute:
        attribute, context = attribute.split('[')
        context = context[:-1]

    X = dict()
    Y = dict()
    for timestamp, _, ev_type, _, ctx, data in t['events']:
        if ev_type == metric_type and attribute in data:
            k = data.get(context, ctx.get(context))
            x = X.get(k, [])
            y = Y.get(k, [])
            x.append(timestamp/(1000.0 if t.get('configuration', {'time_units': 'us'})['time_units'] == 'us' else 1))
            y.append(data[attribute])
            X[k] = x
            Y[k] = y

    for (k, x) in X.items():
        metrics_data.append((x, Y[k], '{}.{}[{}={}]'.format(metric_type, attribute, context, k)))

n_sub = len(metrics_data)
fig, axes = plt.subplots(n_sub, 1, sharex=True, sharey=True)

legends = []
if n_sub == 1:
    axes = [axes]
for (x, y, _), ax in zip(metrics_data, axes):
    l, = ax.plot(x, y, marker='.', picker=True)
    ax.set_xlabel('ms')
    legends.append(l)

plt.xlabel('ms')
plt.legend(legends, [ref for _, _, ref in metrics_data])


def onpick(event):
    line = event.artist
    xdata, ydata = line.get_data()
    ind = event.ind
    for i in ind:
        t = int(xdata[i] * 1000)
        if t in timestamps:
            print(timestamps[t])


fig.canvas.mpl_connect('pick_event', onpick)
plt.show()
