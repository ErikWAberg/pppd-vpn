#import <Cocoa/Cocoa.h>

@interface StatisticsWindowController : NSWindowController <NSWindowDelegate>


@property (weak) IBOutlet NSTextField *sendField;
@property (weak) IBOutlet NSTextField *recvField;
@property (weak) IBOutlet NSTextField *sendrateField;
@property (weak) IBOutlet NSTextField *recvrateField;

@property (weak) IBOutlet NSTextField *clientIpField;
@property (weak) IBOutlet NSTextField *serverIpField;
@property (weak) IBOutlet NSTextField *primaryDnsField;
@property (weak) IBOutlet NSTextField *secondaryDnsField;


- (void) windowOpened;
- (void)loadIOInfo:(NSDictionary*) IOInfo;
- (void)loadAddressInfo;
- (void) handleDisconnect;
@end
