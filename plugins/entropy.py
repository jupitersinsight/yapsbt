import math
from collections import Counter

def shannon_entropy(data):
    if not data:
        return 0
    entropy = 0
    length = len(data)
    counts = Counter(data)
    for count in counts.values():
        p_x = count / length
        entropy += -p_x * math.log(p_x, 2)
    return entropy