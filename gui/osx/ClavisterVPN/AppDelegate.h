#import <Cocoa/Cocoa.h>
#import "StatisticsWindowController.h"

#import "ViewController.h"

@interface AppDelegate : NSObject <NSApplicationDelegate, NSWindowDelegate>


@property StatisticsWindowController* statisticsWindowController;

@property ViewController* viewController;

@property (assign) NSWindow *window;


@property (strong, nonatomic) NSStatusItem *menubarIconStatusItem;
@property (strong, nonatomic) NSMenu *menubarIconMenu;
@property (strong, nonatomic) NSMenuItem *menubarIconMenuStats;
@property (strong, nonatomic) NSMenuItem *menubarIconMenuConnect;
@property (strong, nonatomic) NSMenuItem *menubarIconMenuDisconnect;
@property (strong, nonatomic) NSMenuItem *menubarIconMenuClose;


- (IBAction)openStatisticsWindow:(id)sender;


@property (weak) IBOutlet NSMenuItem *configurationOutlet;

- (IBAction)openConfigurationFile:(id)sender;


- (void)sayHello:(ViewController*) viewController;

- (void) allocMenubar;

- (void) handleNewVpnState:(int) state;

@end

