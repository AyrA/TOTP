﻿/*
 * Derived from https://github.com/google/google-authenticator-android/blob/master/AuthenticatorApp/src/main/java/com/google/android/apps/authenticator/Base32String.java
 * 
 * Copyright (C) 2016 BravoTango86
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

using System;
using System.Text;

namespace TOTP
{
    /// <summary>
    /// Provides functions to convert to and from Base32 strings
    /// </summary>
    public static class Base32
    {
        private static readonly char[] _digits = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".ToCharArray();
        /// <summary>
        /// Mask to extract 5 bits at a time
        /// </summary>
        private const int MASK = 31;
        /// <summary>
        /// Shift value for Base32 bit density (5)
        /// </summary>
        private const int SHIFT = 5;

        /// <summary>
        /// Gets the integer representation (index) of the given character
        /// </summary>
        /// <param name="c">Character</param>
        /// <returns>Index (-1 for error)</returns>
        private static int CharToInt(char c)
        {
            switch (c)
            {
                case 'A': return 0;
                case 'B': return 1;
                case 'C': return 2;
                case 'D': return 3;
                case 'E': return 4;
                case 'F': return 5;
                case 'G': return 6;
                case 'H': return 7;
                case 'I': return 8;
                case 'J': return 9;
                case 'K': return 10;
                case 'L': return 11;
                case 'M': return 12;
                case 'N': return 13;
                case 'O': return 14;
                case 'P': return 15;
                case 'Q': return 16;
                case 'R': return 17;
                case 'S': return 18;
                case 'T': return 19;
                case 'U': return 20;
                case 'V': return 21;
                case 'W': return 22;
                case 'X': return 23;
                case 'Y': return 24;
                case 'Z': return 25;
                case '2': return 26;
                case '3': return 27;
                case '4': return 28;
                case '5': return 29;
                case '6': return 30;
                case '7': return 31;
                //Extra cases for lookalike characters
                case '8': return 1;
                case '0': return 14;
                case '1': return 8;
            }
            return -1;
        }

        /// <summary>
        /// Converts a Base32 string into a byte array
        /// </summary>
        /// <param name="encoded">Base32 string (padding optional)</param>
        /// <returns>Decoded data</returns>
        public static byte[] FromBase32String(string encoded)
        {
            if (encoded == null)
            {
                throw new ArgumentNullException(nameof(encoded));
            }

            // Remove whitespace and padding. Note: the padding is used as hint 
            // to determine how many bits to decode from the last incomplete chunk
            // Also, canonicalize to all upper case
            encoded = encoded.Trim().TrimEnd('=').ToUpper();
            if (encoded.Length == 0)
            {
                return new byte[0];
            }

            var outLength = encoded.Length * SHIFT / 8;
            var result = new byte[outLength];
            var buffer = 0;
            var next = 0;
            var bitsLeft = 0;
            var charValue = 0;
            foreach (var c in encoded)
            {
                charValue = CharToInt(c);
                if (charValue < 0)
                {
                    throw new FormatException($"Illegal character: '{c}'");
                }

                buffer <<= SHIFT;
                buffer |= charValue & MASK;
                bitsLeft += SHIFT;
                if (bitsLeft >= 8)
                {
                    result[next++] = (byte)(buffer >> (bitsLeft - 8));
                    bitsLeft -= 8;
                }
            }

            return result;
        }

        /// <summary>
        /// Converts a byte array into a Base32 string
        /// </summary>
        /// <param name="data">Raw data</param>
        /// <param name="padOutput">true to pad using '='</param>
        /// <returns>Base32 string</returns>
        public static string ToBase32String(byte[] data, bool padOutput = false)
        {
            return ToBase32String(data, 0, data.Length, padOutput);
        }

        /// <summary>
        /// Converts part of a byte array into a Base32 string
        /// </summary>
        /// <param name="data">Raw data</param>
        /// <param name="offset">Data offset</param>
        /// <param name="length">Data length</param>
        /// <param name="padOutput">true to pad using '='</param>
        /// <returns>Base32 string</returns>
        public static string ToBase32String(byte[] data, int offset, int length, bool padOutput = false)
        {
            if (data == null)
            {
                throw new ArgumentNullException(nameof(data));
            }

            if (offset < 0)
            {
                throw new ArgumentOutOfRangeException(nameof(offset));
            }

            if (length < 0)
            {
                throw new ArgumentOutOfRangeException(nameof(length));
            }

            if ((offset + length) > data.Length)
            {
                throw new ArgumentOutOfRangeException();
            }

            if (length == 0)
            {
                return string.Empty;
            }

            // SHIFT is the number of bits per output character, so the length of the
            // output is the length of the input multiplied by 8/SHIFT, rounded up.
            // The computation below will fail, so don't do it.
            if (length >= (1 << 28))
            {
                throw new ArgumentOutOfRangeException(nameof(data));
            }

            var outputLength = (length * 8 + SHIFT - 1) / SHIFT;
            var result = new StringBuilder(outputLength);

            var last = offset + length;
            int buffer = data[offset++];
            var bitsLeft = 8;
            while (bitsLeft > 0 || offset < last)
            {
                if (bitsLeft < SHIFT)
                {
                    if (offset < last)
                    {
                        buffer <<= 8;
                        buffer |= (data[offset++] & 0xff);
                        bitsLeft += 8;
                    }
                    else
                    {
                        int pad = SHIFT - bitsLeft;
                        buffer <<= pad;
                        bitsLeft += pad;
                    }
                }
                int index = MASK & (buffer >> (bitsLeft - SHIFT));
                bitsLeft -= SHIFT;
                result.Append(_digits[index]);
            }
            if (padOutput)
            {
                int padding = 8 - (result.Length % 8);
                if (padding > 0)
                {
                    result.Append('=', padding == 8 ? 0 : padding);
                }
            }
            return result.ToString();
        }
    }
}