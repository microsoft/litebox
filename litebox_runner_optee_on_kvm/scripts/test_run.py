#!/usr/bin/env python3

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

"""Regression tests: kernel smoke success must never masquerade as OP-TEE success."""

import contextlib
import io
import subprocess
import types
import unittest
from unittest.mock import patch

import run


class OpteeResultValidation(unittest.TestCase):
    def kernel_log(self):
        return "\n".join([
            "QEMU-BOOT: shared kernel initialized",
            "QEMU-BOOT: allocation paging protection fault-recovery OK",
            "QEMU-USER: syscall reentry registers XSAVE OK",
            "QEMU-USER: faults isolation teardown OK",
            "QEMU-BOOT: PASS",
        ]) + "\n"

    def full_log(self):
        lines = [self.kernel_log()]
        for ta in ["hello", "hello3seg"]:
            lines.extend([
                f"OPTEE-TEST: {ta} ldelf OK syscalls=13",
                f"OPTEE-TEST: {ta} open-session OK",
                f"OPTEE-TEST: {ta} invoke cmd=0 input=100 output=101 OK",
                f"OPTEE-TEST: {ta} invoke cmd=1 input=200 output=199 OK",
                f"OPTEE-TEST: {ta} invoke cmd=0 input=41 output=42 OK",
                f"OPTEE-TEST: {ta} invalid-command rejected OK",
                f"OPTEE-TEST: {ta} close-session OK syscalls=33 faults=19",
                f"OPTEE-TEST: {ta} PASS",
            ])
        return "\n".join(lines) + "\nOPTEE-TEST: PASS\n"

    def check(self, log, status=33, expected=None):
        args = types.SimpleNamespace(qemu="qemu", accel="tcg", timeout=40)
        result = subprocess.CompletedProcess([], status, log)
        with patch.object(run.subprocess, "run", return_value=result), contextlib.redirect_stdout(io.StringIO()):
            run.run_guest(args, "guest.elf", 128, expected=expected)

    def test_kernel_only_success_is_rejected(self):
        with self.assertRaises(RuntimeError):
            self.check(self.kernel_log())

    def test_complete_optee_results_are_accepted(self):
        self.check(self.full_log())

    def test_each_required_optee_result_is_checked(self):
        full = self.full_log()
        for line in full.splitlines():
            if line.startswith("OPTEE-TEST:"):
                with self.subTest(missing=line), self.assertRaises(RuntimeError):
                    self.check(full.replace(line + "\n", ""))

    def test_wrong_output_and_wrong_status_fail(self):
        with self.assertRaises(RuntimeError):
            self.check(self.full_log().replace("output=101", "output=100"))
        for status in [0, 1, 35, -9]:
            with self.subTest(status=status), self.assertRaises(RuntimeError):
                self.check(self.full_log(), status=status)

    def test_guest_panic_is_not_a_positive_result(self):
        with self.assertRaises(RuntimeError):
            self.check(self.full_log() + "QEMU-BOOT: FAIL panic\n")

    def test_expected_boot_rejections_are_separate(self):
        log = "QEMU-BOOT: FAIL panic: ModulesUnsupported\n"
        self.check(log, status=35, expected="ModulesUnsupported")
        with self.assertRaises(RuntimeError):
            self.check(log, status=35)
        with self.assertRaises(RuntimeError):
            self.check(log, status=35, expected="requires -smp 1")

    def test_timeout_is_a_failure(self):
        args = types.SimpleNamespace(qemu="qemu", accel="tcg", timeout=0.01)
        with patch.object(run.subprocess, "run", side_effect=subprocess.TimeoutExpired([], 0.01)), contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(RuntimeError):
                run.run_guest(args, "guest.elf", 128)


if __name__ == "__main__":
    unittest.main()
