import json
import sys

import matplotlib.pyplot as plt

if len(sys.argv) < 3:
    print('Usage: %s trace_file metric_reference..' % sys.argv[0])
    print('Example: %s server.qlog.json metrics_updated.congestion_window[cc_path] metrics_updated.bytes_in_flight[cc_path] packet_received.header.packet_number[header:dcid]' % sys.argv[0])
    exit(-1)

def deep_get(d, keys):
    for i, k in enumerate(keys):
        if type(d) is list:
            for e in d:
                yield from deep_get(e, keys[i:])
                return
        else:
            d = d.get(k, {})

    if type(d) is dict and not len(d):
        yield None
    else:
        yield d

trace_filename = sys.argv[1]

with open(trace_filename) as f:
    qlog = json.load(f)

t = qlog['traces'][0]

timestamps = {}
for e in t['events']:
    timestamps[e[0]] = e

metrics_data = []
for metric_ref in sys.argv[2:]:
    metric_type, *attributes = metric_ref.split('.')

    context = None
    if '[' in attributes[-1] and ']' in attributes[-1]:
        attributes[-1], context = attributes[-1].split('[')
        context = context[:-1]
        if ':' in context:
            context = context.split(':')
        else:
            context = [context]

    X = dict()
    Y = dict()
    for timestamp, _, ev_type, _, ctx, data in t['events']:
        values = deep_get(data, attributes)
        for value in values:
            if ev_type == metric_type and value is not None:
                k = next(deep_get(data, context))
                if k is None:
                    k = next(deep_get(ctx, context))
                x = X.get(k, [])
                y = Y.get(k, [])
                x.append(timestamp/(1000.0 if t.get('configuration', {'time_units': 'us'})['time_units'] == 'us' else 1))
                y.append(int(value))  # Some qlog integers are encoded as strings
                X[k] = x
                Y[k] = y

    for (k, x) in X.items():
        metrics_data.append((x, Y[k], '{}.{}[{}={}]'.format(metric_type, '.'.join(attributes), '.'.join(context), k)))

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
