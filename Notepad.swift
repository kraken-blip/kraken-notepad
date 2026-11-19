import AppKit
import Security
import ServiceManagement
import SwiftUI

struct Access: Identifiable, Codable {
    var id = UUID()
    var title = ""
    var login = ""
    var icon = "git.branch"
    var link = ""
}

struct Note: Identifiable, Codable {
    var id = UUID()
    var text = ""
}

enum Vault {
    static func query(_ id: UUID) -> [String: Any] {
        [kSecClass as String: kSecClassGenericPassword,
         kSecAttrService as String: "local.dmitry.menu-notepad",
         kSecAttrAccount as String: id.uuidString]
    }

    static func read(_ id: UUID) throws -> String {
        var request = query(id)
        request[kSecReturnData as String] = true
        var result: CFTypeRef?
        let status = SecItemCopyMatching(request as CFDictionary, &result)
        guard status == errSecSuccess, let data = result as? Data,
              let password = String(data: data, encoding: .utf8) else {
            throw NSError(domain: NSOSStatusErrorDomain, code: Int(status == 0 ? errSecDecode : status))
        }
        return password
    }

    static func write(_ password: String, for id: UUID) throws {
        let request = query(id)
        let attributes = [kSecValueData as String: Data(password.utf8)]
        var status = SecItemUpdate(request as CFDictionary, attributes as CFDictionary)
        if status == errSecItemNotFound {
            status = SecItemAdd(request.merging(attributes) { current, _ in current } as CFDictionary, nil)
        }
        guard status == errSecSuccess else {
            throw NSError(domain: NSOSStatusErrorDomain, code: Int(status))
        }
    }
}

final class NotepadLifecycle: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_ notification: Notification) {
        let appPath = Bundle.main.bundleURL.standardizedFileURL.path
        guard !appPath.hasPrefix("/Volumes/"),
              !appPath.contains("/AppTranslocation/"),
              SMAppService.mainApp.status == .notRegistered else { return }
        do {
            try SMAppService.mainApp.register()
        } catch {
            NSLog("Блокнот: %@", error.localizedDescription)
        }
    }
}

@main
struct NotepadApp: App {
    @NSApplicationDelegateAdaptor(NotepadLifecycle.self) private var lifecycle

    var body: some Scene {
        MenuBarExtra {
            NotepadView()
        } label: {
            Label { Text("Блокнот") } icon: { KrakenMark() }
                .labelStyle(.iconOnly)
        }
        .menuBarExtraStyle(.window)
    }
}

private struct KrakenMark: View {
    private static let artwork: NSImage = {
        guard let url = Bundle.main.url(forResource: "kraken-mark", withExtension: "png"),
              let image = NSImage(contentsOf: url) else {
            return NSImage(systemSymbolName: "square.and.pencil", accessibilityDescription: nil) ?? NSImage()
        }
        image.size = NSSize(width: 18, height: 18)
        image.isTemplate = false
        return image
    }()

    var body: some View {
        Image(nsImage: Self.artwork)
    }
}

private enum Palette {
    private static func color(_ light: Int, _ dark: Int) -> Color {
        Color(nsColor: NSColor(name: nil) { appearance in
            let rgb = appearance.bestMatch(from: [.darkAqua, .aqua]) == .darkAqua ? dark : light
            return NSColor(srgbRed: CGFloat(rgb >> 16) / 255,
                           green: CGFloat((rgb >> 8) & 255) / 255,
                           blue: CGFloat(rgb & 255) / 255, alpha: 1)
        })
    }
    static let paper = color(0xfbfafe, 0x232330)
    static let soft = color(0xedebf6, 0x35354a)
    static let line = color(0xdedbe9, 0x484757)
    static let accent = color(0x504382, 0xc8baff)
    static let ink = color(0x272738, 0xf0eef8)
}

private struct BranchIcon: View {
    var body: some View {
        Canvas { context, size in
            let scale = min(size.width, size.height) / 16
            context.scaleBy(x: scale, y: scale)
            var branch = Path()
            branch.move(to: CGPoint(x: 4, y: 4))
            branch.addLine(to: CGPoint(x: 4, y: 12))
            branch.move(to: CGPoint(x: 4, y: 11))
            branch.addQuadCurve(to: CGPoint(x: 12, y: 6), control: CGPoint(x: 12, y: 11))
            for point in [CGPoint(x: 4,y: 2), CGPoint(x: 4,y: 14), CGPoint(x: 12,y: 4)] {
                branch.addEllipse(in: CGRect(x: point.x-1.6,y: point.y-1.6,width: 3.2,height: 3.2))
            }
            context.stroke(branch, with: .color(Palette.ink), lineWidth: 1.5)
        }.accessibilityHidden(true)
    }
}

private struct TileButton: ButtonStyle {
    @Environment(\.isEnabled) private var enabled
    func makeBody(configuration: Configuration) -> some View {
        configuration.label.padding(.horizontal, 8).padding(.vertical, 6)
            .background(Palette.soft, in: RoundedRectangle(cornerRadius: 7))
            .opacity(enabled ? (configuration.isPressed ? 0.7 : 1) : 0.45)
    }
}

final class Panel: ObservableObject {
    @Published var selected: UUID?
    @Published var editing: Access?
    @Published var password = ""
    @Published var status = ""

}

struct NotepadView: View {
    @AppStorage("accesses") private var accessesData = Data()
    @AppStorage("notes") private var notesData = Data()
    @StateObject private var panel = Panel()

    private let icons = ["git.branch", "server.rack", "house", "key"]
    private let iconLabels = ["GitHub", "Сервер", "Админка", "Другое"]
    private var accesses: [Access] {
        (try? JSONDecoder().decode([Access].self, from: accessesData)) ?? []
    }
    private var notes: [Note] {
        (try? JSONDecoder().decode([Note].self, from: notesData)) ?? [Note(), Note()]
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack {
                Label { Text("Блокнот") } icon: { KrakenMark() }
                    .fontWeight(.semibold)
                Spacer()
                Button("Свернуть") {
                    NSApp.keyWindow?.close()
                }
                Button("Выйти") {
                    NSApp.terminate(nil)
                }
            }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(12)
                .background(Palette.soft)
            ScrollView(.horizontal, showsIndicators: false) {
                HStack {
                    tab("Доступы", id: nil)
                    ForEach(Array(notes.enumerated()), id: \.element.id) { index, note in
                        tab("Лист \(index + 1)", id: note.id)
                    }
                    Button {
                        let note = Note()
                        storeNotes(notes + [note])
                        panel.selected = note.id
                        panel.editing = nil
                        panel.password = ""
                        panel.status = ""
                    } label: { Image(systemName: "plus") }
                    .accessibilityLabel("Добавить лист")
                }.padding(10)
            }
            Divider()
            if let selected = panel.selected {
                TextEditor(text: Binding(
                    get: { notes.first { $0.id == selected }?.text ?? "" },
                    set: { text in
                        var updated = notes
                        guard let index = updated.firstIndex(where: { $0.id == selected }) else { return }
                        updated[index].text = text
                        storeNotes(updated)
                    }
                ))
                .accessibilityLabel("Текст заметки")
                .padding(10)
                .frame(height: 245)
            } else {
                ScrollView {
                    VStack(alignment: .leading, spacing: 10) {
                        if let editing = panel.editing { editor(editing) }
                        if accesses.isEmpty && panel.editing == nil {
                            Text("Добавь первый рабочий доступ.").foregroundStyle(.secondary)
                        }
                        LazyVGrid(columns: [GridItem(.adaptive(minimum: 145), spacing: 8)], spacing: 8) {
                            ForEach(accesses) { access in card(access) }
                        }
                        if panel.editing == nil {
                            Button("+ Добавить доступ") {
                                panel.editing = Access()
                                panel.status = ""
                            }
                        }
                        if !panel.status.isEmpty { Text(panel.status).foregroundStyle(.secondary) }
                    }.padding(12)
                }.frame(maxHeight: 395)
            }
        }
        .font(.system(size: 13))
        .background(Palette.paper)
        .foregroundStyle(Palette.ink)
        .buttonStyle(TileButton())
        .tint(Palette.accent)
        .frame(width: 520)
        .onAppear {
            if notesData.isEmpty { storeNotes([Note(), Note()]) }
        }
    }

    private func storeNotes(_ notes: [Note]) {
        if let encoded = try? JSONEncoder().encode(notes) { notesData = encoded }
    }

    private func tab(_ name: String, id: UUID?) -> some View {
        Button(name) {
            panel.selected = id
            panel.editing = nil
            panel.password = ""
            panel.status = ""
        }
        .overlay(RoundedRectangle(cornerRadius: 7).strokeBorder(panel.selected == id ? Palette.accent : .clear))
        .foregroundStyle(panel.selected == id ? Palette.accent : Palette.ink)
    }

    private func card(_ access: Access) -> some View {
        VStack(alignment: .leading, spacing: 7) {
            HStack(spacing: 5) {
                if access.icon == "git.branch" {
                    BranchIcon().frame(width: 15, height: 15)
                } else {
                    Image(systemName: access.icon)
                }
                Text(access.title).fontWeight(.semibold)
            }
            Text(access.login + " · ••••••••").font(.caption).foregroundStyle(.secondary).textSelection(.enabled)
            if let url = URL(string: access.link), ["https", "http"].contains(url.scheme ?? "") {
                Link("Открыть ссылку", destination: url)
            }
            Button("Копировать логин") { copy(access.login, label: "Логин") }
            Button("Копировать пароль") {
                do { copy(try Vault.read(access.id), label: "Пароль", secret: true) }
                catch { panel.status = error.localizedDescription }
            }
            Button("Изменить") {
                panel.editing = access
                panel.password = ""
                panel.status = ""
            }
            .buttonStyle(.link)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(9)
        .background(Palette.paper, in: RoundedRectangle(cornerRadius: 10))
        .overlay(RoundedRectangle(cornerRadius: 10).strokeBorder(Palette.line))
    }

    private func editor(_ access: Access) -> some View {
        let existing = accesses.contains { $0.id == access.id }
        return VStack(alignment: .leading, spacing: 7) {
            Text(existing ? "Изменить доступ" : "Добавить доступ").fontWeight(.semibold)
            TextField("Название", text: field(\.title))
            TextField("Логин", text: field(\.login))
            SecureField(existing ? "Новый пароль (необязательно)" : "Пароль", text: $panel.password)
            TextField("Ссылка (необязательно)", text: field(\.link))
            Picker("Значок", selection: field(\.icon)) {
                ForEach(icons.indices, id: \.self) { index in
                    Text(iconLabels[index]).tag(icons[index])
                }
            }
            HStack {
                Button("Сохранить") { save() }
                    .disabled(access.title.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ||
                              access.login.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || (!existing && panel.password.isEmpty))
                Button("Отмена") { panel.editing = nil; panel.password = ""; panel.status = "" }
            }
        }
    }

    private func field(_ path: WritableKeyPath<Access, String>) -> Binding<String> {
        Binding(get: { panel.editing?[keyPath: path] ?? "" },
                set: { panel.editing?[keyPath: path] = $0 })
    }

    private func save() {
        guard let access = panel.editing else { return }
        var updated = accesses
        if let index = updated.firstIndex(where: { $0.id == access.id }) { updated[index] = access }
        else { updated.append(access) }
        do {
            let encoded = try JSONEncoder().encode(updated)
            if !panel.password.isEmpty { try Vault.write(panel.password, for: access.id) }
            accessesData = encoded
            panel.editing = nil
            panel.password = ""
            panel.status = "Доступ сохранён"
        } catch { panel.status = error.localizedDescription }
    }

    private func copy(_ value: String, label: String, secret: Bool = false) {
        let board = NSPasteboard.general
        board.clearContents()
        let item = NSPasteboardItem()
        item.setString(value, forType: .string)
        if secret { item.setData(Data(), forType: .init("org.nspasteboard.ConcealedType")) }
        guard board.writeObjects([item]) else { panel.status = "Не удалось скопировать"; return }
        panel.status = label + " скопирован"
        if secret {
            let version = board.changeCount
            DispatchQueue.main.asyncAfter(deadline: .now() + 30) {
                if board.changeCount == version { board.clearContents() }
            }
        }
    }
}
