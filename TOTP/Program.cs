using System;
using System.Linq;

namespace TOTP
{
    class Program
    {
        static void Main(string[] args)
        {
            var KEY = "12345678901234567890".Select(m => (byte)m).ToArray();
            Console.Error.WriteLine(Base32.ToBase32String(KEY));
            //*
            do
            {
                Console.Clear();
                Console.Error.WriteLine("TOTP Generated:\t{0}", DateTime.Now.ToLongTimeString());
                var CurrentOffset = HOTP.GetCounter() - 5;
                for (var i = 0; i < 5; i++)
                {
                    Console.Error.WriteLine("TOTP Counter:\t{0}", CurrentOffset + i);
                    Console.Error.WriteLine("TOTP Token:\t{0:000000}", HOTP.GetHOTP(KEY, CurrentOffset + i));
                }
            }
            while (Console.ReadKey(true).Key != ConsoleKey.Escape);
            //*/
            Console.Error.WriteLine("#END");
            Console.ReadKey(true);
        }
    }
}
