#import <Cocoa/Cocoa.h>


@interface ViewController : NSViewController <NSWindowDelegate>  


@property (weak) IBOutlet NSTextField* userField;
@property (weak) IBOutlet NSSecureTextField* passwordField;
@property (weak) IBOutlet NSTextField* addressField;
@property (weak) IBOutlet NSTextField* portField;
@property (weak) IBOutlet NSTextField* fingerprintField;
@property (weak) IBOutlet NSButton *customServerCheckbox;
@property (weak) IBOutlet NSButton *connectButton;
@property (weak) IBOutlet NSButton *cancelButton;


- (IBAction)handleConnect:(id)sender;
- (IBAction)handleCancel:(id)sender;
- (IBAction)handleCustomServer:(id)sender;

- (void)openConfigurationFile:(char*)filePath;

- (void)loadConfigurationVariables;

- (void) hideLoginWindow;

- (void) showLoginWindow;

- (void)handleNewVpnState:(int)state;
@end

