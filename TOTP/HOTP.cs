using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace TOTP
{
    /// <summary>
    /// Provides HOTP and TOTP features
    /// </summary>
    public static class HOTP
    {
        /// <summary>
        /// Default Unix time start offset
        /// </summary>
        private const int UNIX_START = 0;
        /// <summary>
        /// Default token lifetime
        /// </summary>
        private const int STEPSIZE = 30;
        /// <summary>
        /// Default digit count
        /// </summary>
        private const int DIGIT_COUNT = 6;
        /// <summary>
        /// HMAC Algorithm for HOTP.
        /// Default is SHA1
        /// </summary>
        /// <remarks>Changing this renders the algorithm incompatible with its RFC</remarks>
        private const string HMAC_ALGO = "HMACSHA1";
        /// <summary>
        /// The timestamp that represents the start of the unix time
        /// </summary>
        private const string UNIX_TIME = "1970-01-01T00:00:00Z";

        /// <summary>
        /// Generates a secure key
        /// </summary>
        /// <param name="Count">Number of bytes</param>
        /// <returns>Key</returns>
        public static byte[] GetKey(int Count)
        {
            if (Count < 1)
            {
                throw new ArgumentOutOfRangeException(nameof(Count));
            }
            byte[] Ret = new byte[Count];
            using (var RNG = RandomNumberGenerator.Create())
            {
                RNG.GetBytes(Ret);
            }
            return Ret;
        }

        /// <summary>
        /// Generates a HOTP token
        /// </summary>
        /// <param name="Key">Shared secret</param>
        /// <param name="Counter">HOTP Counter. Use <see cref="GetCounter(int, int, DateTime)"/> to use as TOTP</param>
        /// <param name="DigitCount">Number of digits to extract (1-10)</param>
        /// <returns>HOTP token</returns>
        public static int GetHOTP(byte[] Key, long Counter, int DigitCount = DIGIT_COUNT)
        {
            //Verify basic parameter conditions
            if (Counter < 0)
            {
                throw new ArgumentOutOfRangeException(nameof(Counter));
            }
            if (Key == null || Key.Length == 0)
            {
                throw new ArgumentNullException(nameof(Key));
            }
            if (DigitCount < 1 || DigitCount > 10)
            {
                throw new ArgumentOutOfRangeException(nameof(DigitCount));
            }

            //Convert integer to an 8 byte big endian byte array and discard the sign bit
            var CounterBytes = new byte[] {
                (byte)(Counter >> 56 & 0x7F),
                (byte)(Counter >> 48 & 0xFF),
                (byte)(Counter >> 40 & 0xFF),
                (byte)(Counter >> 32 & 0xFF),
                (byte)(Counter >> 24 & 0xFF),
                (byte)(Counter >> 16 & 0xFF),
                (byte)(Counter >> 8 & 0xFF),
                (byte)(Counter & 0xFF)
            };

            using (var Hasher = HMAC.Create(HMAC_ALGO))
            {
                //Compute the HMAC of the data
                Hasher.Key = Key;
                var Result = Hasher.ComputeHash(CounterBytes);

                //Get the offset we extract data from. This can range from 0 to 15
                var ResultOffset = Result[Result.Length - 1] & 0x0F;

                //Convert byte array to big endian 4 byte integer and discard sign bit
                var ResultDigits =
                    (Result[ResultOffset + 0] << 24 & 0x7F000000) |
                    Result[ResultOffset + 1] << 16 |
                    Result[ResultOffset + 2] << 8 |
                    Result[ResultOffset + 3];

                //Return the Number that is the token.
                return ResultDigits % (int)Math.Pow(10, DigitCount);
                //Note:
                //You are supposed to pad the number to the left with zeros to ensure it's "DigitCount" digits long.
                //You can do this using "SomeNumber.ToString("".PadRight(DigitCount,'0'));"
            }
        }

        /// <summary>
        /// Gets the counter value to convert <see cref="GetHOTP(byte[], long, int)"/> into a TOTP function
        /// </summary>
        /// <param name="UnixStart">
        /// Start offset of unix time. This is usually zero
        /// </param>
        /// <param name="StepSize">
        /// Step size of the counter. This is usually 30
        /// </param>
        /// <param name="Now">
        /// Date to use as current timestamp.
        /// Default is to use the current time.
        /// Can be used to create past/future tokens
        /// </param>
        /// <returns>Counter for <see cref="GetHOTP(byte[], long, int)"/></returns>
        public static int GetCounter(int UnixStart = UNIX_START, int StepSize = STEPSIZE, DateTime Now = default(DateTime))
        {
            if (Now == default(DateTime))
            {
                Now = DateTime.UtcNow;
            }
            else if (Now.Kind != DateTimeKind.Utc)
            {
                Now = Now.ToUniversalTime();
            }
            //Calculates the start of the counter for the seconds
            var Epoch = DateTime.Parse(UNIX_TIME).AddSeconds(UNIX_START).ToUniversalTime();
            //Calculates the total elapsed seconds since the Epoch
            var UnixTime = (int)DateTime.UtcNow.Subtract(Epoch).TotalSeconds;
            //Calculates the counter itself.
            //Note: Integer division is naturally rounded down
            return UnixTime / StepSize;
        }
    }
}
