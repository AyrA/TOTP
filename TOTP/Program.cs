using System;
using System.Linq;
using System.Security.Cryptography;

namespace TOTP
{
    class Program
    {
        //public const string CHARSET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

        static void Main(string[] args)
        {
            var KEY = "12345678901234567890".Select(m => (byte)m).ToArray();
            Console.Error.WriteLine(Base32.ToBase32String(KEY));
            /*
            do
            {
                Console.Clear();
                Console.Error.WriteLine("TOTP Generated:\t{0}", DateTime.Now.ToLongTimeString());
                var CurrentOffset = GetCounter();
                Console.Error.WriteLine("TOTP Counter:\t{0}", CurrentOffset);
                Console.Error.WriteLine("TOTP Token:\t{0:000000}", TOTP(KEY, CurrentOffset));
            }
            while (Console.ReadKey(true).Key != ConsoleKey.Escape);
            //*/
            Console.Error.WriteLine("#END");
            Console.ReadKey(true);
        }
    }
}
