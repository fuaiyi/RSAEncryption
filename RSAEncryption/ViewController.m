//
//  ViewController.m
//  RSAEncryption
//
//  Created by gaofu on 2017/4/21.
//  Copyright © 2017年 gaofu. All rights reserved.
//

#import "ViewController.h"
#import "EncryptTool.h"


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
