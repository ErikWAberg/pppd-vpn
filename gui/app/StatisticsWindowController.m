#import "StatisticsWindowController.h"
#import "AppDelegate.h"
#import "NSOperation+StatisticsOperation.h"

//C-Includes
#import "vpn.h"

@interface StatisticsWindowController ()

@end

@implementation StatisticsWindowController

@synthesize sendField;
@synthesize recvField;
@synthesize sendrateField;
@synthesize recvrateField;

@synthesize clientIpField;
@synthesize serverIpField;
@synthesize primaryDnsField;
@synthesize secondaryDnsField;


StatisticsOperation* statisticsOperation;
NSOperationQueue *operationQueue;


static bool visibleWindow;

- (void)windowDidLoad {
    [super windowDidLoad];
    NSLog(@"UI: Statistics windowDidLoad.");
}

- (void) windowOpened {
    NSLog(@"UI: Statistics windowOpened.");
    visibleWindow = true;
    [self loadAddressInfo];
    [self.window setDelegate:self];
    statisticsOperation = [[StatisticsOperation alloc] init];
    operationQueue = [[NSOperationQueue alloc] init];
    
    [[NSNotificationCenter defaultCenter]  addObserver:self
           selector:@selector(statisticsUpdateNotification:)
               name:@"StatisticsNotification"
             object:statisticsOperation];
    
    [operationQueue addOperation:statisticsOperation];
}

- (void)windowWillClose:(NSNotification *)notification {
    NSLog(@"UI: Statistics windowWillClose");
    visibleWindow = false;
    [statisticsOperation cancel];
    [[NSNotificationCenter defaultCenter] removeObserver:self];
    
}

- (void) handleDisconnect {
    [recvrateField setStringValue: @"0 kB/s 0 kbit/s"];
    [sendrateField setStringValue: @"0 kB/s 0 kbit/s"];
}


- (void)statisticsUpdateNotification:(NSNotification *)notification
{
    if(!visibleWindow) NSLog(@"Received statistics notification, NO WINDOW");
    
    if ([[notification name] isEqualToString:@"StatisticsNotification"]) {
        [self loadIOInfo:notification.userInfo];
    }
}

- (void)loadIOInfo:(NSDictionary*) IOInfo {
    if([IOInfo objectForKey:@"bytes_in"])
        [recvField setStringValue: [IOInfo valueForKey:@"bytes_in"]];
    if([IOInfo objectForKey:@"bytes_in"])
        [sendField setStringValue: [IOInfo valueForKey:@"bytes_out"]];
    if([IOInfo objectForKey:@"bytes_in"])
        [recvrateField setStringValue: [IOInfo valueForKey:@"rate_in"]];
    if([IOInfo objectForKey:@"bytes_in"])
        [sendrateField setStringValue: [IOInfo valueForKey:@"rate_out"]];
    
}

- (void)loadAddressInfo {
    int state = vpn_get_state();
    
    if(state == VPN_CONNECTED) {
        
     //   NSLog(@"state %d", state);
        
        const char* ip = vpn_get_local_ip();
        if(ip) {
            [clientIpField setStringValue: [NSString stringWithFormat:@"%s", ip]];
        }
        
        const char* server_ip = vpn_get_remote_ip();
        if(server_ip) {
            [serverIpField setStringValue: [NSString stringWithFormat:@"%s", server_ip]];
        }
        
        const char* dns1 = vpn_get_primary_dns();
        if(dns1) {
            [primaryDnsField setStringValue: [NSString stringWithFormat:@"%s", dns1]];
        }
        
        const char* dns2 = vpn_get_secondary_dns();
        if(dns2) {
            [secondaryDnsField setStringValue: [NSString stringWithFormat:@"%s", dns2]];
        }
        
    }
}




@end
