import AppKit
import Foundation

@MainActor
final class AppMenuBuilder {
    func buildMenu(
        target: AnyObject,
        onRuntimeStatusItem: NSMenuItem,
        onOpenItem: NSMenuItem,
        onPreferencesItem: NSMenuItem,
        onRestartItem: NSMenuItem,
        onDataDirectoryItem: NSMenuItem,
        onLaunchAtLoginItem: NSMenuItem,
        onUninstallItem: NSMenuItem,
        onQuitItem: NSMenuItem
    ) -> NSMenu {
        let menu = NSMenu()
        menu.addItem(onRuntimeStatusItem)
        menu.addItem(.separator())

        onOpenItem.target = target
        menu.addItem(onOpenItem)
        menu.addItem(.separator())

        onPreferencesItem.target = target
        menu.addItem(onPreferencesItem)
        menu.addItem(.separator())

        onRestartItem.target = target
        menu.addItem(onRestartItem)
        menu.addItem(.separator())

        onDataDirectoryItem.target = target
        menu.addItem(onDataDirectoryItem)
        menu.addItem(.separator())

        onLaunchAtLoginItem.target = target
        menu.addItem(onLaunchAtLoginItem)
        menu.addItem(.separator())

        onUninstallItem.target = target
        menu.addItem(onUninstallItem)
        onQuitItem.target = target
        menu.addItem(onQuitItem)
        return menu
    }
}
