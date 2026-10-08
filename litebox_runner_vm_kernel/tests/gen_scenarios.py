#!/usr/bin/env python3

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

"""Generates the *-cmds.json scenarios here, with their expected TA outputs
and live-instance counts. Requires the `cryptography` package.

Clients keep sessions open and interleave their work, so every instance's
state must survive switches to other instances.
"""

import base64
import json
import os

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

HERE = os.path.dirname(os.path.abspath(__file__))
TA_TESTS = os.path.join(HERE, "../../litebox_runner_optee_on_linux_userland/tests")

# TA header flags of the single-instance TAs; the others are multi-instance.
SINGLE_INSTANCE = {"kmpp-ta": {"keep_alive": True}}
MAX_INSTANCES = 16
BAD_PARAMETERS, OUT_OF_MEMORY, TARGET_DEAD = 0xFFFF0006, 0xFFFF000C, 0xFFFF3024


def b64(data):
    return base64.b64encode(data).decode()


def blocks(count, seed):
    return bytes((seed * 31 + i * 7) & 0xFF for i in range(16 * count))


class Scenario:
    """Commands plus a model of the TA manager, for `expect_instances`."""

    def __init__(self):
        self.cmds = []
        self.sessions = {}  # label -> instance, or None once it died
        self.instances = {}  # instance -> [ta, sessions]
        self.next_instance = 0

    def emit(self, cmd, check_instances=True):
        if check_instances:
            cmd["expect_instances"] = len(self.instances)
        self.cmds.append(cmd)

    def open(self, ta, label, args=None, expect=None):
        cmd = {"func_id": "open_session", "ta": ta, "session": label}
        if args:
            cmd["args"] = args
        if expect is not None:
            cmd["expect_result"] = expect
        else:
            shared = [i for i, (t, _) in self.instances.items() if t == ta and ta in SINGLE_INSTANCE]
            if shared:
                instance = shared[0]
            else:
                assert len(self.instances) < MAX_INSTANCES
                self.next_instance += 1
                instance = self.next_instance
                self.instances[instance] = [ta, 0]
            self.instances[instance][1] += 1
            self.sessions[label] = instance
        self.emit(cmd)

    def invoke(self, label, cmd_id, args=(), expect=None, check_instances=False):
        cmd = {"func_id": "invoke_command", "session": label, "cmd_id": cmd_id}
        if args:
            cmd["args"] = list(args)
        if expect is not None:
            cmd["expect_result"] = expect
        self.emit(cmd, check_instances)

    def die(self, label):
        """The next command kills `label`'s instance; its sessions stay until closed."""
        instance = self.sessions[label]
        del self.instances[instance]
        for other, i in self.sessions.items():
            if i == instance:
                self.sessions[other] = None

    def close(self, label):
        instance = self.sessions.pop(label)
        if instance in self.instances:
            entry = self.instances[instance]
            entry[1] -= 1
            keep_alive = SINGLE_INSTANCE.get(entry[0], {}).get("keep_alive")
            if entry[1] == 0 and not keep_alive:
                del self.instances[instance]
        self.emit({"func_id": "close_session", "session": label})

    def write(self, name):
        with open(os.path.join(HERE, f"{name}-cmds.json"), "w") as f:
            f.write("[\n" + ",\n".join("  " + json.dumps(c) for c in self.cmds) + "\n]\n")


def hello(s, label, cmd_id, a, b=7):
    """hello3seg-ta, hello-ta in three segments: 0 increments value_a, 1
    decrements it."""
    expected = a + 1 if cmd_id == 0 else a - 1
    s.invoke(label, cmd_id, [{"param_type": "value_inout", "value_a": a, "value_b": b,
                              "expect_value_a": expected, "expect_value_b": b}])


class Aes:
    """aes-ta: 0 prepares (algorithm, key size, mode), 1 sets the key, 2 the
    IV, 3 ciphers. The OP-TEE shim implements only CTR, and the TA takes 128-
    and 256-bit keys. A cipher stream continues across commands."""

    CTR = 2

    def __init__(self, s, label, key, iv, encrypt):
        self.s, self.label, self.key, self.iv, self.encrypt = s, label, key, iv, encrypt
        cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
        self.stream = cipher.encryptor() if encrypt else cipher.decryptor()

    def prepare(self):
        self.s.invoke(self.label, 0, [
            {"param_type": "value_input", "value_a": self.CTR, "value_b": 0},
            {"param_type": "value_input", "value_a": len(self.key), "value_b": 0},
            {"param_type": "value_input", "value_a": int(self.encrypt), "value_b": 0},
        ])

    def set_key(self):
        self.s.invoke(self.label, 1, [{"param_type": "memref_input", "data_base64": b64(self.key)}])

    def set_iv(self, expect=None):
        self.s.invoke(self.label, 2, [{"param_type": "memref_input", "data_base64": b64(self.iv)}],
                      expect=expect, check_instances=expect is not None)

    def setup(self):
        self.prepare()
        self.set_key()
        self.set_iv()

    def cipher(self, data):
        out = self.stream.update(data)
        self.s.invoke(self.label, 3, [
            {"param_type": "memref_input", "data_base64": b64(data)},
            {"param_type": "memref_output", "buffer_size": len(data),
             "expect_size": len(out), "expect_data_base64": b64(out)},
        ])
        return out


def kmpp_open(s, label):
    s.open("kmpp-ta", label, [
        {"param_type": "value_input", "value_a": 1, "value_b": 0},
        {"param_type": "value_output", "expect_value_a": 4, "expect_value_b": 1},
    ])


with open(os.path.join(TA_TESTS, "kmpp-ta-cmds.json")) as f:
    KMPP_INPUTS = [c["args"][0]["data_base64"] for c in json.load(f)
                   if c["func_id"] == "invoke_command"]


def kmpp(s, label, which):
    """kmpp-ta's output is randomized, so only its size is checked."""
    s.invoke(label, 7, [
        {"param_type": "memref_input", "data_base64": KMPP_INPUTS[which]},
        {"param_type": "memref_output", "buffer_size": 300, "expect_size": 300},
    ])


def random(s, label, size, expect=None):
    arg = {"param_type": "memref_output", "buffer_size": size}
    if expect is None:
        arg["expect_size"] = size
    s.invoke(label, 0, [arg], expect=expect, check_instances=expect is not None)


K128 = bytes(range(0x00, 0x10))
K256 = bytes(range(0x40, 0x60))
K256B = bytes(range(0x60, 0x80))
IV1 = bytes(range(0xA0, 0xB0))
IV2 = bytes(range(0xC0, 0xD0))


def concurrent_sessions():
    """Every TA kind at once: three AES instances (one decrypting another's
    output), hello3seg, a shared keep-alive kmpp instance, and random."""
    s = Scenario()
    ctr = Aes(s, "ctr", K128, IV1, encrypt=False)
    enc = Aes(s, "enc", K256, IV2, encrypt=True)
    dec = Aes(s, "dec", K256, IV2, encrypt=False)
    s.open("aes-ta", "ctr")
    s.open("hello3seg-ta", "h1")
    s.open("aes-ta", "enc")
    ctr.prepare()
    hello(s, "h1", 0, 100)
    enc.prepare()
    kmpp_open(s, "k1")
    s.open("aes-ta", "dec")
    s.open("random-ta", "r")
    ctr.set_key()
    enc.set_key()
    dec.prepare()
    random(s, "r", 32)
    ctr.set_iv()
    dec.set_key()
    hello(s, "h1", 1, 101)
    enc.set_iv()
    dec.set_iv()
    kmpp(s, "k1", 0)
    ciphertexts = []
    for i, plaintext in enumerate([blocks(2, 1), blocks(3, 2), blocks(1, 3), blocks(4, 4)]):
        ctr.cipher(blocks(2, 10 + i))
        ciphertexts.append(enc.cipher(plaintext))
        hello(s, "h1", i % 2, 1000 + i)
        if i == 1:
            kmpp_open(s, "k2")
            kmpp(s, "k2", 1)
            s.open("hello3seg-ta", "h2")
        if i >= 1:
            hello(s, "h2", 0, 50 + i)
            kmpp(s, "k1" if i % 2 else "k2", i % 2)
        random(s, "r", 16 * (i + 1))
        if i == 2:
            random(s, "r", 17 << 20, expect=BAD_PARAMETERS)
    for ciphertext in ciphertexts:
        dec.cipher(ciphertext)
        ctr.cipher(blocks(1, 20))
    s.close("k1")
    kmpp(s, "k2", 0)
    s.close("h1")
    s.invoke("h1", 0, [{"param_type": "value_inout", "value_a": 1, "value_b": 0}],
             expect=BAD_PARAMETERS, check_instances=True)
    ctr.cipher(blocks(3, 30))
    hello(s, "h2", 1, 9)
    s.close("enc")
    s.close("k2")
    kmpp_open(s, "k3")
    kmpp(s, "k3", 1)
    dec.cipher(enc.stream.update(blocks(2, 40)))
    s.close("dec")
    s.close("r")
    hello(s, "h2", 0, 77)
    s.close("ctr")
    s.close("k3")
    s.close("h2")
    s.write("concurrent-sessions")


def ta_death():
    """An AES instance panics while others are mid-stream; they carry on."""
    s = Scenario()
    a1 = Aes(s, "a1", K128, IV1, encrypt=True)
    a2 = Aes(s, "a2", K256B, IV2, encrypt=True)
    s.open("aes-ta", "a1")
    s.open("hello3seg-ta", "h")
    s.open("aes-ta", "a2")
    a1.setup()
    hello(s, "h", 0, 1)
    a2.setup()
    a1.cipher(blocks(2, 1))
    a2.cipher(blocks(2, 2))
    hello(s, "h", 1, 2)
    s.open("aes-ta", "bad")
    # The IV before PREPARE: TEE_CipherInit on a null handle panics the TA.
    s.die("bad")
    Aes(s, "bad", K128, IV1, encrypt=True).set_iv(expect=TARGET_DEAD)
    a1.cipher(blocks(1, 3))
    hello(s, "h", 0, 3)
    s.invoke("bad", 3, expect=TARGET_DEAD, check_instances=True)
    a2.cipher(blocks(3, 4))
    s.close("bad")
    s.open("aes-ta", "good")
    good = Aes(s, "good", K128, IV1, encrypt=True)
    good.setup()
    good.cipher(blocks(2, 1))
    a1.cipher(blocks(2, 5))
    s.close("a1")
    a2.cipher(blocks(1, 6))
    good.cipher(blocks(1, 7))
    s.close("h")
    s.close("good")
    s.close("a2")
    s.write("ta-death")


def instance_churn():
    """Rounds of filling every instance slot, overflowing, and closing half,
    with work in every live session between them."""
    s = Scenario()
    live, ciphers, count = [], {}, 0

    def new_session():
        nonlocal count
        count += 1
        if len(live) % 3 == 0:
            label = f"a{count}"
            s.open("aes-ta", label)
            ciphers[label] = Aes(s, label, bytes([count]) * 16, bytes([count + 1]) * 16, True)
            ciphers[label].setup()
        else:
            label = f"h{count}"
            s.open("hello3seg-ta", label)
            hello(s, label, 0, count)
        live.append(label)

    def work(label, i):
        if label in ciphers:
            ciphers[label].cipher(blocks(1, i))
        else:
            hello(s, label, i % 2, 10 * i)

    for round in range(3):
        while len(s.instances) < MAX_INSTANCES:
            new_session()
        s.open("hello3seg-ta", "overflow", expect=OUT_OF_MEMORY)
        for i, label in enumerate(live):
            work(label, i + round)
        for label in live[round::2][:8]:
            s.close(label)
            ciphers.pop(label, None)
        live = [label for label in live if label in s.sessions]
        for i, label in enumerate(live):
            work(label, i + 7)
    for label in list(live):
        work(label, 3)
        s.close(label)
    s.write("instance-churn")


concurrent_sessions()
ta_death()
instance_churn()
