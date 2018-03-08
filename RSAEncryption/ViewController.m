//
//  ViewController.m
//  RSAEncryption
//
//  Created by gaofu on 2017/4/21.
//  Copyright © 2017年 gaofu. All rights reserved.
//

#import "ViewController.h"
#import "EncryptTool.h"
#import "RSAEncryptor.h"

@interface ViewController ()

@end

@implementation ViewController
{
    __weak IBOutlet UITextView *_inputTextView;
    __weak IBOutlet UITextView *_outputTextView;
}

- (void)viewDidLoad
{
    [super viewDidLoad];
    // Do any additional setup after loading the view, typically from a nib.
    
    
    
    ;
    
    
    
    
    
//    //原始数据
    NSString *originalString = @"这是一段将要使用'.der'文件加密的字符串!这是一段将要使用'.der'文件加密的字符串!这是一段将要使用'.der'文件加密的字符串!这是一段将要使用'.der'文件加密的字符串!这是一段将要使用'.der'文件加密的字符串!这是一段将要使用'.der'文件加密的字符串!这是一段将要使用'.der'文件加密的字符串!这是一段将要使用'.der'文件加密的字符串!这是一段将要使用'.der'文件加密的字符串!这是一段将要使用'.der'文件加密的字符串!这是一段将要使用'.der'文件加密的字符串!这是一段将要使用'.der'文件加密的字符串!这是一段将要使用'.der'文件加密的字符串!";
//
//    //使用.der和.p12中的公钥私钥加密解密
//    NSString *public_key_path = [[NSBundle mainBundle] pathForResource:@"public_key.pem" ofType:nil];
//    NSString *private_key_path = [[NSBundle mainBundle] pathForResource:@"private_key.pem" ofType:nil];
    
    NSString *encryptStr = [RSAEncryptor encryptString:originalString publicKey:@"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDLyQGhLLE9+xtR5ZzPv1vMEOIvYJxEcMbapskPqqlYewyXD5esHa/BZwQgMTPDMSFw4TuXOUWaM/Khelon8p4iKF4O4m1Uc5AmEY+vM4gITg1KkmyuN2f43insnBWkMiV8dhfeIB/pCCAL1RExrBfehIVdkwe3bemsNnowLIyOHwIDAQAB"];
    NSLog(@"加密前:%@", originalString);
    NSLog(@"加密后:%@", encryptStr);
    NSLog(@"解密后:%@", [RSAEncryptor decryptString:encryptStr privateKey:@"MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAMvJAaEssT37G1HlnM+/W8wQ4i9gnERwxtqmyQ+qqVh7DJcPl6wdr8FnBCAxM8MxIXDhO5c5RZoz8qF6WifyniIoXg7ibVRzkCYRj68ziAhODUqSbK43Z/jeKeycFaQyJXx2F94gH+kIIAvVETGsF96EhV2TB7dt6aw2ejAsjI4fAgMBAAECgYBNu8wCVhD6CpoeQE7ztBPpIJuW5OxW8wn3h910O25DkRR5XvpFLkHHrWsWeI49K7WM4G2hvrf9HUm1LP3M9TA6OxZ4yvnrr5d7s6vSFiLxOdTwiS0b6ZcCFu29lN6baNOO9rh84inoBhROKLFkCzwyQEtMFwxeXsHQdxWJU8Og0QJBAObmlQi5QojFlJmkYsF+9G8blcs3nLstRoxWxQjw83m9Bl6Y0wT5scPSBGUg3jtQhe4efJY2TgjVpKG+CgfnkycCQQDh790Lbwr4Cmdo1GSvWDD594d5MHLvo7caQHnZqCdhu8onBr48ICQzBp7HwUDjhSBnUjMU1lqBBb3xeNrkvqhJAkEAoslVsPzLh5mkll1qsnhK5DpSdR8UBHJ7Fl3mM9OME/vMDc04mH1hcmkSaCmwA6lVgvdDZrOKeHgGxXExqTj+aQJBAMB7kizAgG7Kpki30cNUdf0vNVo4vWKNblvOHEEjMdHgo5tV8lHU7CIQfMsfSAHNk8qSS/RvnZEX7DdBR/LivwkCQEZ2p6QHZ3BGK/8GuanmQ8TuTVl7bipazkmuk2RQZ0UqBjxB6NfGy+PKB5iNMinsM/E+JxjbB25lQNPIOyW/wJA="]);
    
    
    
}

- (IBAction)encryptionClick:(UIButton *)sender
{
    //公钥加密
    NSString * result = [[EncryptTool shareInstance] encrypt:_inputTextView.text type:eKeyTypePublic];
    _outputTextView.text = result.length ? result : @"加密失败!";
}

- (IBAction)decryptionClick:(UIButton *)sender
{
    //私钥解密
    NSString * result = [[EncryptTool shareInstance] decrypt:_inputTextView.text type:eKeyTypePrivate];
    _outputTextView.text = result.length ? result : @"解密失败!";
}


@end
