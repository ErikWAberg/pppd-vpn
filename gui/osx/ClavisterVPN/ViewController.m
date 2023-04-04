#import "ViewController.h"
#import "AppDelegate.h"

//C-Includes

#include <arpa/inet.h>
#include "vpn.h"
#include "config.h"
@implementation ViewController



@synthesize userField;
@synthesize passwordField;
@synthesize addressField;
@synthesize portField;
@synthesize fingerprintField;
@synthesize customServerCheckbox;
@synthesize connectButton;
@synthesize cancelButton;


static bool clientStarted = false;
static struct VPN_CONFIG vpn_config;
static bool useVPNConfig = false;

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view.

    self.cancelButton.enabled = NO;
    AppDelegate* appDelegate= (AppDelegate*)[NSApp delegate];
    [appDelegate sayHello:self];
    
    
}

- (void)setRepresentedObject:(id)representedObject {
    [super setRepresentedObject:representedObject];

    // Update the view, if already loaded.
}

-(void) startVpnThread:(struct VPN_CONFIG*)vpn_config
{
    self.connectButton.enabled = NO;
    self.cancelButton.enabled = YES;
    clientStarted = true;
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0), ^{
        vpn_init_with_configuration(3, vpn_config);
        vpn_connect();

    });
}


- (void)viewDidAppear {
    self.view.window.delegate = self;
}

- (void)handleNewVpnState:(int)state {
    switch(state) {
        case VPN_DISCONNECTED:
            [self.view.window setIsVisible:YES];
            self.connectButton.enabled = YES;
            self.cancelButton.enabled = NO;
            clientStarted = NO;
            break;
            
        case VPN_CONNECTED:
            self.connectButton.enabled = NO;
            self.cancelButton.enabled = YES;
            clientStarted = NO;
            [self.view.window setIsVisible:NO];
            break;
            
        case VPN_CONNECTING:
            break;
        default:
            break;
    }

}

- (IBAction)handleConnect:(id)sender {
    
    int state = vpn_get_state();
    
    if(state == VPN_CONNECTED) return;

    if(useVPNConfig) {
        if(passwordField.stringValue.length > 0) {
            const char* password = [[passwordField stringValue] UTF8String];
            strncpy(vpn_config.user_password, password, strlen(password));
            
            [self startVpnThread:&vpn_config];

        } else {
            NSAlert *alert = [[NSAlert alloc] init];
            [alert setMessageText:@"Empty password"];
            [alert setInformativeText:@"Please insert your password."];
            [alert addButtonWithTitle:@"Ok"];
            [alert runModal];
        }

    } else {
        if([customServerCheckbox state] != NSOnState) {
            NSAlert *alert = [[NSAlert alloc] init];
            [alert setMessageText:@"VPN server not specified"];
            [alert setInformativeText:@"Please choose a configuration file or insert custom server attributes."];
            [alert addButtonWithTitle:@"Ok"];
            [alert runModal];
        } else {
            if(userField.stringValue.length > 0 && passwordField.stringValue.length > 0 &&
               addressField.stringValue.length > 0 && portField.stringValue.length > 0 &&
                fingerprintField.stringValue.length > 0) {
                const char* user = [[userField stringValue] UTF8String];
                const char* password = [[passwordField stringValue] UTF8String];
                
                const char* address = [[addressField stringValue] UTF8String];
                const int port = [portField intValue];
                const char* fingerprint = [[fingerprintField stringValue] UTF8String];
                
                NSLog(@"User: %s, address: %s, port: %d\nfingerprint:%s", user, address, port, fingerprint);
               
                vpn_config.server_port = port;
                strcpy(vpn_config.server_hostname, address);
                strncpy(vpn_config.server_ssl_fingerprint, fingerprint, strlen(fingerprint));
                strncpy(vpn_config.user_name, user, strlen(user));
                strncpy(vpn_config.user_password, password, strlen(password));
                
                [self startVpnThread:&vpn_config];
            } else {
                NSAlert *alert = [[NSAlert alloc] init];
                [alert setMessageText:@"Missing values"];
                [alert setInformativeText:@"Please specify all details before attempting to connect."];
                [alert addButtonWithTitle:@"Ok"];
                [alert runModal];
            }
        }
    }
    
}


- (void) showLoginWindow {
    [self.view.window setIsVisible:YES];
}

- (void) hideLoginWindow {
        [self.view.window setIsVisible:NO];
}

- (IBAction)handleCancel:(id)sender {
    NSLog(@"handleCancel");

    if(clientStarted) {
        clientStarted = false;
        vpn_terminate();
        self.connectButton.enabled = YES;
        self.cancelButton.enabled = NO;
    }
}


- (void)windowWillClose:(NSNotification *)notification {
    NSLog(@"Main windowWillClose");
    
}

- (void)toggleFields:(BOOL)stateValue {
    self.addressField.enabled = stateValue;
    self.portField.enabled = stateValue;
    self.fingerprintField.enabled = stateValue;
}

- (IBAction)handleCustomServer:(id)sender {
    if([customServerCheckbox state] == NSOnState) {
        NSLog(@"UI:Custom server enabled.");
        [self toggleFields:YES];
        
    } else {
        NSLog(@"UI:Custom server disabled.");
        [self toggleFields:NO];
    }
}

- (void)openConfigurationFile:(char*)filePath {
    NSLog(@"Reading config %s", filePath);
    if(vpn_config_read(&vpn_config, filePath) == 0) {
        NSLog(@"Configuration file successfully read.");
        useVPNConfig = true;
        [self loadConfigurationVariables];
    }
    
}

- (void)loadConfigurationVariables {
    userField.stringValue = [NSString stringWithFormat:@"%s", vpn_config.user_name];
    addressField.stringValue = [NSString stringWithFormat:@"%s", vpn_config.server_hostname];
    portField.stringValue = [NSString stringWithFormat:@"%d", (int) vpn_config.server_port];
    fingerprintField.stringValue = [NSString stringWithFormat:@"%s", vpn_config.server_ssl_fingerprint];
}


@end
