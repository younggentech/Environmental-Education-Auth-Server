import math
import random


def generate_otp(digits: int = 6) -> str:
    """Generates OTP for verification"""
    alphabet = '0987612345'
    otp = ''
    for i in range(digits):
        otp += alphabet[math.floor(random.random() * 10)]
    return otp
