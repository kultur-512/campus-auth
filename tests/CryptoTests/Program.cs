using CampusAuth;

string u = "20230001";
string md5 = SrunCrypto.Md5Hex("Passw0rd!");
string p = "{MD5}" + md5;
string ip = "172.32.18.219";
string acid = "1";

string info = SrunCrypto.BuildInfo(u, p, ip, acid);
string chk = SrunCrypto.BuildChecksum(u, p, acid, ip, info);

Console.WriteLine("md5:  " + md5);
Console.WriteLine("info: " + info);
Console.WriteLine("chk:  " + chk);

string expectMd5 = "47b7bfb65fa83ac9a71dcb0f6296bb6e";
string expectInfo = "{SRBX1}MHiguH500JyoNCMkIi20VOwEHpF5CWgf0g6plgU15bqrukhCoABqOvfuXUv7Vstx/la6Ue+WW1gcWuDpU41t5UrVjlSbNa6aKdwU3u91mf2T/Fd4ZUe1ttD90NmlHYZGQCLyiOhHfCxVrmAYRHGD5gI2RP7QAiDOXF+Ryi2Y3UXC36Xn";
string expectChk = "ec08c4ac4a43ed1ec02a9a521f535e3d";

Console.WriteLine();
Console.WriteLine("md5  匹配: " + (md5 == expectMd5));
Console.WriteLine("info 匹配: " + (info == expectInfo));
Console.WriteLine("chk  匹配: " + (chk == expectChk));
