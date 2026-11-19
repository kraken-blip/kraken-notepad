import AppKit
import CryptoKit
import Darwin
import Security
import ServiceManagement
import SwiftUI

struct Access: Identifiable, Codable {
    var id = UUID()
    var title = ""
    var login = ""
    var icon = "git.branch"
    var link = ""
    var description: String?
}

struct Note: Identifiable, Codable {
    var id = UUID()
    var name: String?
    var textColor: NoteTextColor?
    var text = ""
}

private enum NotepadIdentity {
    static let current = "local.kraken.menu-notepad"

    // The fingerprint identifies the previous preferences domain without shipping its name.
    static let previous: String? = {
        let fingerprint = "24479291f7f53358f6f39855babaf7c097af6ade26df589a289a7d655461b1cf"
        let directory = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Preferences", isDirectory: true)
        let files = (try? FileManager.default.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil)) ?? []
        return files.lazy.filter { $0.pathExtension == "plist" }
            .map { $0.deletingPathExtension().lastPathComponent }
            .first { domain in
                guard domain.hasPrefix("local."), domain.hasSuffix(".menu-notepad") else { return false }
                return SHA256.hash(data: Data(domain.utf8)).map { String(format: "%02x", $0) }.joined() == fingerprint
            }
    }()

    static func importPreferences() {
        guard let previous, let old = UserDefaults.standard.persistentDomain(forName: previous) else { return }
        let defaults = UserDefaults.standard
        for key in ["accesses", "notes", "accessTextColor"] where defaults.object(forKey: key) == nil {
            if let value = old[key] { defaults.set(value, forKey: key) }
        }
    }
}

enum Vault {
    private static let service = NotepadIdentity.current
    private static let sharedAccount = "passwords-v2"

    static func read(_ id: UUID) throws -> String {
        try withLock {
            var entries = try load()
            if let password = entries[id.uuidString] { return password }

            guard let previous = NotepadIdentity.previous,
                  let legacy = try readData(id.uuidString, service: previous) else {
                throw keychainError(errSecItemNotFound)
            }
            guard let password = String(data: legacy, encoding: .utf8) else {
                throw keychainError(errSecDecode)
            }
            entries[id.uuidString] = password
            try save(entries)
            try? remove(id.uuidString, service: previous)
            return password
        }
    }

    static func write(_ password: String, for id: UUID) throws {
        try withLock {
            var entries = try load()
            entries[id.uuidString] = password
            try save(entries)
        }
    }

    static func delete(_ id: UUID) throws {
        try withLock {
            var entries = try load()
            if let previous = NotepadIdentity.previous {
                try remove(id.uuidString, service: previous)
            }
            if entries.removeValue(forKey: id.uuidString) != nil {
                try save(entries)
            }
        }
    }

    private static func load() throws -> [String: String] {
        let decoder = JSONDecoder()
        var entries = try readData(sharedAccount).map { try decoder.decode([String: String].self, from: $0) } ?? [:]
        if let previous = NotepadIdentity.previous,
           let legacy = try readData(sharedAccount, service: previous) {
            let olderEntries = try decoder.decode([String: String].self, from: legacy)
            entries.merge(olderEntries) { current, _ in current }
            try save(entries)
            try remove(sharedAccount, service: previous)
        }
        return entries
    }

    private static func save(_ entries: [String: String]) throws {
        let request = query(sharedAccount)
        let attributes = [kSecValueData as String: try JSONEncoder().encode(entries)]
        var status = SecItemUpdate(request as CFDictionary, attributes as CFDictionary)
        if status == errSecItemNotFound {
            status = SecItemAdd(request.merging(attributes) { current, _ in current } as CFDictionary, nil)
        }
        guard status == errSecSuccess else { throw keychainError(status) }
    }

    private static func query(_ account: String, service: String = service) -> [String: Any] {
        [kSecClass as String: kSecClassGenericPassword,
         kSecAttrService as String: service,
         kSecAttrAccount as String: account]
    }

    private static func readData(_ account: String, service: String = service) throws -> Data? {
        var request = query(account, service: service)
        request[kSecReturnData as String] = true
        var result: CFTypeRef?
        let status = SecItemCopyMatching(request as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let data = result as? Data else {
            throw keychainError(status == errSecSuccess ? errSecDecode : status)
        }
        return data
    }

    private static func remove(_ account: String, service: String) throws {
        let status = SecItemDelete(query(account, service: service) as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw keychainError(status)
        }
    }

    private static func keychainError(_ status: OSStatus) -> NSError {
        NSError(domain: NSOSStatusErrorDomain, code: Int(status))
    }

    private static func withLock<T>(_ operation: () throws -> T) throws -> T {
        let base = try FileManager.default.url(for: .applicationSupportDirectory, in: .userDomainMask,
                                               appropriateFor: nil, create: true)
        let directory = base.appendingPathComponent(service, isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let lock = directory.appendingPathComponent("vault.lock")
        let fd = open(lock.path, O_CREAT | O_RDWR | O_NOFOLLOW, S_IRUSR | S_IWUSR)
        guard fd >= 0 else { throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno)) }
        defer { close(fd) }
        guard flock(fd, LOCK_EX | LOCK_NB) == 0 else {
            throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno))
        }
        return try operation()
    }
}

final class NotepadLifecycle: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_ notification: Notification) {
        NotepadIdentity.importPreferences()
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
            Label { Text("Блокнот").foregroundStyle(Palette.accent) } icon: { KrakenMark() }
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

enum NoteTextColor: String, CaseIterable, Codable {
    case standard, orange, blue, green

    init(from decoder: Decoder) throws {
        let raw = try decoder.singleValueContainer().decode(String.self)
        self = Self(rawValue: raw) ?? .standard
    }

    var label: String {
        switch self {
        case .standard: "Белый (по умолчанию)"
        case .orange: "Оранжевый"
        case .blue: "Голубой"
        case .green: "Зелёный"
        }
    }

    var color: Color {
        switch self {
        case .standard: Palette.ink
        case .orange: Palette.accent
        case .blue: Palette.color(0x125796, 0x8ecaff)
        case .green: Palette.color(0x286341, 0x8de2a4)
        }
    }
}

private enum Palette {
    static func color(_ light: Int, _ dark: Int) -> Color {
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
    static let accent = color(0x9a431d, 0xffa96d)
    static let copyIcon = color(0x0966c2, 0x55aaff)
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
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    func makeBody(configuration: Configuration) -> some View {
        let pressed = enabled && configuration.isPressed
        let shape = RoundedRectangle(cornerRadius: 7)
        return configuration.label.padding(.horizontal, 8).padding(.vertical, 6)
            .background {
                if pressed {
                    shape.fill(Palette.soft.shadow(.inner(color: .black.opacity(0.32), radius: 2, y: 1)))
                } else {
                    shape.fill(Palette.soft)
                }
            }
            .contentShape(shape)
            .offset(y: pressed && !reduceMotion ? 2 : 0)
            .opacity(enabled ? 1 : 0.45)
    }
}

enum DeletionTarget {
    case access(UUID)
    case note(UUID, name: String)
}

final class Panel: ObservableObject {
    @Published var selected: UUID?
    @Published var editing: Access?
    @Published var password = ""
    @Published var status = ""
    @Published var deleting: DeletionTarget?
    @Published var renaming: UUID?
    @Published var showingPalette = false
    @Published var noteName = ""
    @Published var accesses: [Access] = []
    var lastAccessCount = 0
    @Published var revealed: (id: UUID, value: String)?
    @Published var passwordEdit: UUID?
    @Published var passwordDraft = ""

    func hidePassword() {
        revealed = nil
    }

    func cancelPasswordEdit() {
        passwordEdit = nil
        passwordDraft = ""
    }

}

struct NotepadView: View {
    @AppStorage("accesses") private var accessesData = Data()
    @AppStorage("notes") private var notesData = Data()
    @AppStorage("accessTextColor") private var accessTextColor: NoteTextColor = .standard
    @StateObject private var panel = Panel()
    @FocusState private var nameFocused: Bool
    @FocusState private var passwordFocused: Bool

    private let panelWidth: CGFloat = 620
    private let panelPadding: CGFloat = 12
    private let cardSpacing: CGFloat = 10
    private let cardsPerPage = 3
    private let contentHeight: CGFloat = 310
    private let accessStatusHeight: CGFloat = 16
    private let accessStatusSpacing: CGFloat = 6
    private var cardHeight: CGFloat { contentHeight - 2 * panelPadding - accessStatusHeight - accessStatusSpacing }

    private let icons = ["externaldrive", "switch.2", "git.branch", "server.rack", "house", "key"]
    private let iconLabels = ["VPS", "3x-UI", "GitHub", "Сервер", "Админка", "Другое"]
    private var accesses: [Access] { panel.accesses }
    private var notes: [Note] {
        (try? JSONDecoder().decode([Note].self, from: notesData)) ?? [Note(), Note()]
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack {
                Label { Text("Блокнот").foregroundStyle(Palette.accent) } icon: { KrakenMark() }
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
            HStack(spacing: 8) {
                tab("Доступы", id: nil)
                ScrollView(.horizontal, showsIndicators: false) {
                    HStack {
                        ForEach(Array(notes.enumerated()), id: \.element.id) { index, note in
                            noteTab(note, defaultName: "Лист \(index + 1)")
                        }
                        Button {
                            let note = Note()
                            storeNotes(notes + [note])
                            select(note.id)
                        } label: { Image(systemName: "plus") }
                        .accessibilityLabel("Добавить лист")
                    }
                }
                if panel.selected == nil {
                    paletteButton("Цвет текста доступов", color: accessTextColor)
                    iconButton("plus", label: "Добавить доступ", color: Palette.accent) {
                        panel.hidePassword()
                        panel.cancelPasswordEdit()
                        panel.editing = Access()
                        panel.password = ""
                        panel.status = ""
                    }
                    .disabled(panel.editing != nil)
                } else if let id = panel.selected {
                    paletteButton("Цвет текста листа", color: noteColor(id))
                    iconButton("trash", label: "Удалить открытый лист", role: .destructive) {
                        let currentNotes = notes
                        guard let index = currentNotes.firstIndex(where: { $0.id == id }) else { return }
                        let name = currentNotes[index].name ?? "Лист \(index + 1)"
                        panel.deleting = .note(id, name: name)
                    }
                    .disabled(panel.renaming != nil)
                }
            }.padding(10)
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
                .foregroundColor(noteColor(selected).color)
                .accessibilityLabel("Текст заметки")
                .padding(10)
                .frame(height: contentHeight)
            } else {
                VStack(alignment: .leading, spacing: accessStatusSpacing) {
                    ZStack(alignment: .topLeading) {
                        if accesses.isEmpty {
                            Text("Добавь первый рабочий доступ.").foregroundStyle(.secondary)
                        } else {
                            accessStrip
                        }
                    }
                    .frame(maxWidth: .infinity, alignment: .topLeading)
                    .frame(height: cardHeight, alignment: .topLeading)
                    .allowsHitTesting(panel.editing == nil)
                    .accessibilityHidden(panel.editing != nil)
                    .overlay {
                        if let editing = panel.editing {
                            ScrollView {
                                editor(editing)
                                    .frame(maxWidth: .infinity, alignment: .leading)
                            }
                            .background(Palette.paper)
                        }
                    }
                    Text(panel.status)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                        .frame(height: accessStatusHeight, alignment: .leading)
                        .help(panel.status)
                }
                .padding(panelPadding)
                .frame(width: panelWidth, height: contentHeight, alignment: .topLeading)
            }
        }
        .disabled(panel.deleting != nil)
        .accessibilityHidden(panel.deleting != nil)
        .overlay {
            switch panel.deleting {
            case let .access(id):
                if let access = accesses.first(where: { $0.id == id }) {
                    deletionPopup("Удалить доступ?", name: access.title,
                                  detail: "Пароль будет удалён из Связки ключей.") {
                        delete(id)
                    }
                }
            case let .note(id, name):
                deletionPopup("Удалить лист?", name: name, detail: "Текст листа будет удалён.") {
                    deleteNote(id)
                }
            case nil:
                EmptyView()
            }
        }
        .font(.system(size: 13))
        .background(Palette.paper)
        .foregroundStyle(Palette.ink)
        .buttonStyle(TileButton())
        .tint(Palette.accent)
        .frame(width: panelWidth)
        .onAppear {
            loadAccesses(accessesData)
            if notesData.isEmpty { storeNotes([Note(), Note()]) }
        }
        .onChange(of: accessesData, perform: loadAccesses)
        .onReceive(NotificationCenter.default.publisher(for: NSWindow.didResignKeyNotification)) { _ in
            panel.hidePassword()
        }
        .onDisappear {
            panel.showingPalette = false
            panel.hidePassword()
            panel.cancelPasswordEdit()
        }
    }

    private var accessStrip: some View {
        let viewportWidth = panelWidth - 2 * panelPadding
        let cardWidth = (viewportWidth - CGFloat(cardsPerPage - 1) * cardSpacing) / CGFloat(cardsPerPage)

        return ScrollViewReader { proxy in
            let cards = HStack(alignment: .top, spacing: cardSpacing) {
                ForEach(accesses) { access in
                    card(access)
                        .frame(width: cardWidth)
                        .id(access.id)
                }
            }
            Group {
                if #available(macOS 15, *) {
                    ScrollView(.horizontal) { cards.scrollTargetLayout() }
                        .scrollTargetBehavior(.viewAligned(limitBehavior: .alwaysByOne))
                } else if #available(macOS 14, *) {
                    ScrollView(.horizontal) { cards.scrollTargetLayout() }
                        .scrollTargetBehavior(.viewAligned)
                } else {
                    ScrollView(.horizontal) { cards }
                }
            }
            .scrollIndicators(.hidden)
            .frame(width: viewportWidth, height: cardHeight)
            .accessibilityLabel("Карточки доступов")
            .onChange(of: accesses.count) { count in
                if count > panel.lastAccessCount, let lastCard = accesses.last {
                    proxy.scrollTo(lastCard.id, anchor: .trailing)
                }
                panel.lastAccessCount = count
            }
            .onAppear { panel.lastAccessCount = accesses.count }
        }
    }

    private func loadAccesses(_ data: Data) {
        panel.accesses = (try? JSONDecoder().decode([Access].self, from: data)) ?? []
    }

    private func noteColor(_ id: UUID) -> NoteTextColor {
        notes.first { $0.id == id }?.textColor ?? .standard
    }

    private func paletteButton(_ label: String, color: NoteTextColor) -> some View {
        HStack(spacing: 4) {
            if panel.showingPalette {
                paletteSwatches(selected: color)
            }
            iconButton("paintpalette", label: label, color: color.color) {
                panel.showingPalette.toggle()
            }
        }
        .fixedSize(horizontal: true, vertical: false)
        .onExitCommand {
            panel.showingPalette = false
        }
    }

    private func paletteSwatches(selected: NoteTextColor) -> some View {
        HStack(spacing: 2) {
            ForEach(NoteTextColor.allCases, id: \.self) { color in
                Button {
                    chooseTextColor(color)
                } label: {
                    let swatch = RoundedRectangle(cornerRadius: 3)
                    swatch.fill(color == .standard ? Color.white : color.color)
                        .overlay {
                            if color == selected {
                                Image(systemName: "checkmark")
                                    .font(.system(size: 7, weight: .bold))
                                    .foregroundStyle(Color.black)
                                    .padding(1)
                                    .background(.white, in: Circle())
                            }
                        }
                        .frame(width: 14, height: 14)
                        .padding(3)
                        .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .help(color.label)
                .accessibilityLabel(color.label)
                .accessibilityAddTraits(color == selected ? .isSelected : [])
            }
        }
        .padding(4)
        .background(Palette.paper, in: RoundedRectangle(cornerRadius: 9))
        .overlay(RoundedRectangle(cornerRadius: 9).strokeBorder(Palette.line).allowsHitTesting(false))
    }

    private func chooseTextColor(_ color: NoteTextColor) {
        panel.showingPalette = false
        guard let id = panel.selected else {
            accessTextColor = color
            return
        }
        var updated = notes
        guard let index = updated.firstIndex(where: { $0.id == id }) else { return }
        updated[index].textColor = color
        storeNotes(updated)
    }

    private func storeNotes(_ notes: [Note]) {
        if let encoded = try? JSONEncoder().encode(notes) { notesData = encoded }
    }

    private func deleteNote(_ id: UUID) {
        var updated = notes
        guard let index = updated.firstIndex(where: { $0.id == id }) else {
            panel.deleting = nil
            return
        }
        updated.remove(at: index)
        storeNotes(updated)
        panel.deleting = nil
        if panel.selected == id {
            select(updated.isEmpty ? nil : updated[min(index, updated.count - 1)].id)
        }
    }

    private func select(_ id: UUID?) {
        guard panel.selected != id else { return }
        if panel.renaming != nil { finishRename() }
        panel.selected = id
        panel.showingPalette = false
        panel.hidePassword()
        panel.cancelPasswordEdit()
        if panel.deleting != nil { panel.deleting = nil }
        if panel.editing != nil { panel.editing = nil }
        if !panel.password.isEmpty { panel.password = "" }
        if !panel.status.isEmpty { panel.status = "" }
    }

    private func tab(_ name: String, id: UUID?) -> some View {
        Button {
            select(id)
        } label: {
            Text(name).lineLimit(1).frame(maxWidth: id == nil ? nil : 150)
        }
        .overlay(RoundedRectangle(cornerRadius: 7).strokeBorder(panel.selected == id ? Palette.accent : .clear).allowsHitTesting(false))
        .foregroundStyle(panel.selected == id ? Palette.accent : Palette.ink)
    }

    @ViewBuilder
    private func noteTab(_ note: Note, defaultName: String) -> some View {
        let name = note.name ?? defaultName
        if panel.renaming == note.id {
            TextField("Название листа", text: $panel.noteName)
                .frame(width: 145)
                .focused($nameFocused)
                .onAppear { nameFocused = true }
                .onSubmit { finishRename() }
                .onExitCommand { panel.renaming = nil }
        } else {
            tab(name, id: note.id)
                .simultaneousGesture(TapGesture(count: 2).onEnded { startRename(note.id, name: name) })
                .contextMenu {
                    Button("Переименовать") { startRename(note.id, name: name) }
                }
        }
    }

    private func startRename(_ id: UUID, name: String) {
        select(id)
        panel.noteName = name
        panel.renaming = id
    }

    private func finishRename() {
        guard let id = panel.renaming else { return }
        var updated = notes
        if let index = updated.firstIndex(where: { $0.id == id }) {
            let name = panel.noteName.trimmingCharacters(in: .whitespacesAndNewlines)
            updated[index].name = name.isEmpty ? nil : name
            storeNotes(updated)
        }
        panel.renaming = nil
    }

    private func card(_ access: Access) -> some View {
        VStack(alignment: .leading, spacing: 7) {
            HStack(spacing: 5) {
                if access.icon == "git.branch" {
                    BranchIcon().frame(width: 15, height: 15)
                } else {
                    Image(systemName: access.icon)
                }
                Text(access.title).fontWeight(.semibold).lineLimit(2).foregroundStyle(accessTextColor.color).help(access.title)
                Spacer(minLength: 0)
                iconButton("square.on.square", label: "Скопировать название или адрес", color: Palette.copyIcon) {
                    copy(access.title, label: "Адрес или название", success: "Скопировано")
                }
            }
            credentialRow("Логин", value: access.login) {
                copy(access.login, label: "Логин")
            }
            passwordRow(access)
            Button {
                startAccessEdit(access)
            } label: {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Описание").foregroundStyle(.secondary)
                    if let description = access.description, !description.isEmpty {
                        Text(description)
                            .foregroundStyle(accessTextColor.color)
                            .lineLimit(3)
                    }
                }
                .font(.caption)
                .frame(maxWidth: .infinity, alignment: .leading)
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .help("Редактировать описание")
            Spacer(minLength: 0)
            HStack(spacing: 6) {
                iconButton("slider.horizontal.3", label: "Изменить доступ") {
                    startAccessEdit(access)
                }
                Spacer(minLength: 0)
                passwordControls(access.id)
                if let url = URL(string: access.link), ["https", "http"].contains(url.scheme ?? "") {
                    Link(destination: url) {
                        Image(systemName: "arrow.up.right.square")
                    }
                    .help("Открыть ссылку")
                    .accessibilityLabel("Открыть ссылку")
                }
                Spacer(minLength: 0)
                iconButton("trash", label: "Удалить доступ", role: .destructive) {
                    panel.hidePassword()
                    panel.cancelPasswordEdit()
                    panel.deleting = .access(access.id)
                }
            }
        }
        .padding(9)
        .frame(maxWidth: .infinity, alignment: .topLeading)
        .frame(height: cardHeight, alignment: .topLeading)
        .background(Palette.paper, in: RoundedRectangle(cornerRadius: 10))
        .overlay(RoundedRectangle(cornerRadius: 10).strokeBorder(Palette.line))
    }

    private func credentialRow(_ name: String, value: String, multiline: Bool = false,
                               action: @escaping () -> Void) -> some View {
        HStack(spacing: 8) {
            VStack(alignment: .leading, spacing: 2) {
                Text(name).font(.caption).foregroundStyle(.secondary)
                Text(value).lineLimit(multiline ? nil : 1).truncationMode(.middle)
                    .foregroundStyle(accessTextColor.color).textSelection(.enabled)
            }
            Spacer(minLength: 0)
            iconButton("square.on.square", label: "Скопировать: " + name.lowercased(),
                       color: Palette.copyIcon, action: action)
        }
    }

    private func passwordRow(_ access: Access) -> some View {
        let visible = panel.revealed?.id == access.id
        let editing = panel.passwordEdit == access.id
        return VStack(alignment: .leading, spacing: 5) {
            credentialRow("Пароль", value: visible ? panel.revealed?.value ?? "" : "••••••••",
                          multiline: visible) {
                do { copy(try Vault.read(access.id), label: "Пароль", secret: true) }
                catch { panel.status = error.localizedDescription }
            }

            if editing {
                SecureField("Новый пароль", text: $panel.passwordDraft)
                    .focused($passwordFocused)
                    .onAppear { passwordFocused = true }
                    .onSubmit { savePassword(access.id) }
                    .onExitCommand { panel.cancelPasswordEdit() }
                HStack(spacing: 6) {
                    Button("Сохранить") { savePassword(access.id) }
                        .disabled(panel.passwordDraft.isEmpty)
                    Button("Отмена") { panel.cancelPasswordEdit() }
                }
            }
        }
    }

    private func passwordControls(_ id: UUID) -> some View {
        let visible = panel.revealed?.id == id
        return HStack(spacing: 4) {
            iconButton(visible ? "eye" : "eye.slash",
                       label: visible ? "Скрыть пароль" : "Показать пароль") {
                togglePassword(id)
            }
            iconButton("pencil", label: "Изменить пароль") {
                guard panel.passwordEdit != id else {
                    passwordFocused = true
                    return
                }
                panel.hidePassword()
                panel.passwordDraft = ""
                panel.passwordEdit = id
            }
        }
        .accessibilityElement(children: .contain)
        .accessibilityLabel("Действия с паролем")
    }

    private func iconButton(_ symbol: String, label: String, color: Color = Palette.ink,
                            role: ButtonRole? = nil, action: @escaping () -> Void) -> some View {
        Button(role: role, action: action) {
            Image(systemName: symbol)
                .foregroundStyle(color)
                .frame(width: 12, height: 16)
        }
        .help(label)
        .accessibilityLabel(label)
    }

    private func togglePassword(_ id: UUID) {
        if panel.revealed?.id == id {
            panel.hidePassword()
            return
        }
        panel.hidePassword()
        do { panel.revealed = (id, try Vault.read(id)) }
        catch { panel.status = error.localizedDescription }
    }

    private func savePassword(_ id: UUID) {
        guard panel.passwordEdit == id, !panel.passwordDraft.isEmpty else { return }
        do {
            try Vault.write(panel.passwordDraft, for: id)
            panel.hidePassword()
            panel.cancelPasswordEdit()
            panel.status = "Пароль сохранён"
        } catch { panel.status = error.localizedDescription }
    }

    private func deletionPopup(_ title: String, name: String, detail: String,
                               confirm: @escaping () -> Void) -> some View {
        ZStack {
            Color.black.opacity(0.24)
                .onTapGesture { panel.deleting = nil }
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 10) {
                Text(title).font(.headline)
                Text(name).lineLimit(2)
                Text(detail)
                    .foregroundStyle(.secondary)
                HStack {
                    Spacer()
                    Button("Нет") { panel.deleting = nil }
                        .keyboardShortcut(.cancelAction)
                    Button("Да", role: .destructive, action: confirm)
                }
            }
            .padding(14)
            .frame(width: 245)
            .background(Palette.paper, in: RoundedRectangle(cornerRadius: 12))
            .overlay(RoundedRectangle(cornerRadius: 12).strokeBorder(Palette.line).allowsHitTesting(false))
            .shadow(color: .black.opacity(0.22), radius: 14, y: 4)
        }
    }

    private func startAccessEdit(_ access: Access) {
        panel.hidePassword()
        panel.cancelPasswordEdit()
        panel.editing = access
        panel.password = ""
        panel.status = ""
    }

    private func editor(_ access: Access) -> some View {
        let existing = accesses.contains { $0.id == access.id }
        return VStack(alignment: .leading, spacing: 7) {
            Text(existing ? "Изменить доступ" : "Добавить доступ").fontWeight(.semibold)
            TextField("Название", text: field(\.title))
            TextField("Логин", text: field(\.login))
            SecureField(existing ? "Новый пароль (необязательно)" : "Пароль", text: $panel.password)
            TextField("Ссылка (необязательно)", text: field(\.link))
            VStack(alignment: .leading, spacing: 3) {
                Text("Описание (необязательно)").foregroundStyle(.secondary)
                TextEditor(text: Binding(
                    get: { panel.editing?.description ?? "" },
                    set: { panel.editing?.description = $0.isEmpty ? nil : $0 }
                ))
                .scrollContentBackground(.hidden)
                .frame(height: 54)
                .background(Palette.soft, in: RoundedRectangle(cornerRadius: 5))
                .accessibilityLabel("Описание")
            }
            .font(.caption)
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
            if !panel.password.isEmpty {
                try Vault.write(panel.password, for: access.id)
                panel.hidePassword()
            }
            accessesData = encoded
            panel.editing = nil
            panel.password = ""
            panel.status = "Доступ сохранён"
        } catch { panel.status = error.localizedDescription }
    }

    private func delete(_ id: UUID) {
        do {
            let remaining = accesses.filter { $0.id != id }
            let encoded = try JSONEncoder().encode(remaining)
            try Vault.delete(id)
            accessesData = encoded
            panel.accesses = remaining
            if panel.editing?.id == id {
                panel.editing = nil
                panel.password = ""
            }
            panel.deleting = nil
            panel.status = "Доступ удалён"
        } catch {
            panel.deleting = nil
            panel.status = error.localizedDescription
        }
    }

    private func copy(_ value: String, label: String, secret: Bool = false, success: String? = nil) {
        let board = NSPasteboard.general
        board.clearContents()
        let item = NSPasteboardItem()
        item.setString(value, forType: .string)
        if secret { item.setData(Data(), forType: .init("org.nspasteboard.ConcealedType")) }
        guard board.writeObjects([item]) else { panel.status = "Не удалось скопировать"; return }
        panel.status = success ?? (label + " скопирован")
        if secret {
            let version = board.changeCount
            DispatchQueue.main.asyncAfter(deadline: .now() + 30) {
                if board.changeCount == version { board.clearContents() }
            }
        }
    }
}
