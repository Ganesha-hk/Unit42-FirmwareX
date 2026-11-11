import random

def seeds(protocol,seed=42):
    rng=random.Random(seed)
    if protocol=='http':
        values=[b'GET / HTTP/1.0\r\n\r\n',b'GET / HTTP/1.0\r\nContent-Length: -1\r\n\r\n',b'POST / HTTP/1.0\r\nContent-Length: 0\r\n\r\n']
    elif protocol=='upnp':
        values=[b'M-SEARCH * HTTP/1.1\r\nMX: 1\r\n\r\n',b'M-SEARCH * HTTP/1.1\r\nMX: -1\r\n\r\n',b'M-SEARCH * HTTP/1.1\r\nMX: 0\r\n\r\n']
    elif protocol=='mqtt':values=[bytes.fromhex('100f00044d5154540402003c0003667778'),b'\x10\xff\xff\xff\xff\x01',b'\x10\x00']
    else:raise ValueError('unsupported protocol')
    mutated=bytearray(values[0]);mutated[rng.randrange(len(mutated))]^=1<<rng.randrange(8)
    return values+[bytes(mutated)]

def minimize(payload,reproduces,max_attempts=24):
    """Bounded deletion reduction; no claim of globally minimal input."""
    attempts=0;chunk=max(1,len(payload)//2)
    while chunk and attempts<max_attempts:
        changed=False
        for start in range(0,len(payload),chunk):
            if attempts>=max_attempts:break
            candidate=payload[:start]+payload[start+chunk:]
            if not candidate:continue
            attempts+=1
            if reproduces(candidate):payload=candidate;changed=True;break
        if not changed:chunk//=2
    return payload,attempts
