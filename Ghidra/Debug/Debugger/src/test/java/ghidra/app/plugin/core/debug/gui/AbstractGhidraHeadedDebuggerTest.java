/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.app.plugin.core.debug.gui;

import static org.junit.Assert.*;

import java.awt.*;
import java.awt.event.*;
import java.awt.image.BufferedImage;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;

import javax.swing.*;
import javax.swing.tree.TreePath;

import org.jdom.JDOMException;
import org.junit.*;
import org.junit.rules.TestName;

import db.Transaction;
import docking.ActionContext;
import docking.DefaultActionContext;
import docking.action.ActionContextProvider;
import docking.action.DockingActionIf;
import docking.widgets.table.DynamicTableColumn;
import docking.widgets.tree.GTree;
import docking.widgets.tree.GTreeNode;
import ghidra.GhidraTestApplicationLayout;
import ghidra.app.nav.Navigatable;
import ghidra.app.plugin.core.debug.gui.action.BasicAutoReadMemorySpec;
import ghidra.app.plugin.core.debug.gui.model.ObjectTableModel.ValueRow;
import ghidra.app.plugin.core.debug.gui.model.columns.TraceValueObjectPropertyColumn;
import ghidra.app.plugin.core.debug.service.target.DebuggerTargetServicePlugin;
import ghidra.app.plugin.core.debug.service.tracemgr.DebuggerTraceManagerServicePlugin;
import ghidra.app.services.*;
import ghidra.app.util.viewer.listingpanel.ListingPanel;
import ghidra.async.AsyncTestUtils;
import ghidra.debug.api.action.*;
import ghidra.docking.settings.SettingsImpl;
import ghidra.framework.model.*;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.*;
import ghidra.program.model.data.DataType;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.Program;
import ghidra.program.util.*;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;
import ghidra.trace.database.ToyDBTraceBuilder;
import ghidra.trace.model.Trace;
import ghidra.trace.model.target.schema.SchemaContext;
import ghidra.trace.model.target.schema.XmlSchemaContext;
import ghidra.util.*;
import ghidra.util.datastruct.TestDataStructureErrorHandlerInstaller;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.ConsoleTaskMonitor;
import utility.application.ApplicationLayout;

public abstract class AbstractGhidraHeadedDebuggerTest
		extends AbstractGhidraHeadedIntegrationTest implements AsyncTestUtils {

	/**
	 * Any test that uses staticall-initialized variables with any real complexity runs the risk of
	 * invoking the logger before said logger has been initialized. The abstract test case is
	 * responsible for initializing it, and it affords its subclasses the opportunity to override
	 * things like the application layout and configuration. Thus, we cannot initialize the
	 * application in the static initializer here. What will happen, then, is the logger will be
	 * partially initialized, and the XML config files refer to system properties that will not have
	 * been set yet. This manifests in strange files being created in the tests' working
	 * directories, e.g., <code>${sys:logFilename}</code>.
	 * 
	 * <p>
	 * A cheap hack to avoid this issue is to just initialize those system properties to some temp
	 * file. Once the logging system is initialized, the variables will be overwritten by the
	 * application config and the logger re- and fully-initialized. For what it's worth, the logging
	 * config for the test case is going to be a file in a temp directory, anyway. As long as it's
	 * cleaned up by the JVM or the OS, we should be happy. I just want to ensure they're not
	 * showing up in git commits.
	 * 
	 * <p>
	 * TODO: Should this hack be moved up into the super classes of the Ghidra Test framework?
	 */
	static {
		try {
			System.setProperty("logFilename",
				Files.createTempFile("ghidraTest", ".log").toString());
			System.setProperty("scriptLogFilename",
				Files.createTempFile("ghidraTestScript", ".log").toString());
		}
		catch (IOException e) {
			throw new AssertionError(e);
		}
	}

	@Override
	protected ApplicationLayout createApplicationLayout() throws IOException {
		return new GhidraTestApplicationLayout(new File(getTestDirectoryPath())) {
			@Override
			protected Set<String> getDependentModulePatterns() {
				Set<String> patterns = super.getDependentModulePatterns();
				patterns.add("Debugger-agent");
				return patterns;
			}
		};
	}

	public static final String LANGID_TOYBE64 = "Toy:BE:64:default";

	protected static byte[] arr(String hex) {
		return NumericUtilities.convertStringToBytes(hex);
	}

	protected static SchemaContext xmlSchema(String xml) {
		try {
			return XmlSchemaContext.deserialize(xml);
		}
		catch (JDOMException e) {
			throw new AssertionError(e);
		}
	}

	protected static void assertNoElement(Supplier<?> supplier) {
		// Give the element a chance to appear
		try {
			Thread.sleep(DEFAULT_WAIT_DELAY);
		}
		catch (InterruptedException e1) {
			// Whatever
		}
		try {
			Object value = supplier.get();
			fail("Expected NoSuchElementException. Got " + value);
		}
		catch (NoSuchElementException e) {
			// Good
		}
	}

	protected static void assertTypeEquals(DataType expected, DataType actual) {
		if (expected == null && actual == null) {
			return;
		}
		if (expected == null || actual == null) {
			assertEquals(expected, actual);
		}
		if (!actual.isEquivalent(expected) || expected.isEquivalent(actual)) {
			return;
		}
		assertEquals(expected, actual);
	}

	/**
	 * Works like {@link #waitForValue(Supplier)}, except this caches {@link NoSuchElementException}
	 * and tries again.
	 *
	 * @param <T> the type of object to wait for
	 * @param supplier the supplier of the object
	 * @return the object
	 */
	protected static <T> T waitForElement(Supplier<T> supplier) {
		return waitForValue(() -> {
			try {
				return supplier.get();
			}
			catch (NoSuchElementException e) {
				return null;
			}
		});
	}

	protected static void waitForNoElement(Supplier<?> supplier) {
		waitForValue(() -> {
			try {
				supplier.get();
				return null;
			}
			catch (NoSuchElementException e) {
				return new Object();
			}
		});
	}

	/**
	 * This is so gross
	 *
	 * @param lockable
	 */
	protected void waitForLock(DomainObject lockable) {
		waitForPass(() -> {
			assertTrue(lockable.lock(null));
			lockable.unlock();
		});
	}

	/**
	 * Get an address in the trace's default space
	 *
	 * @param trace the trace
	 * @param offset the byte offset in the default space
	 * @return the address
	 */
	protected static Address addr(Trace trace, long offset) {
		return trace.getBaseAddressFactory().getDefaultAddressSpace().getAddress(offset);
	}

	/**
	 * Get an address in the program's default space
	 *
	 * @param program the program
	 * @param offset the byte offset in the default space
	 * @return the address
	 */
	protected static Address addr(Program program, long offset) {
		return program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
	}

	/**
	 * Get an address range in the trace's default space
	 *
	 * @param program the program
	 * @param min the min byte offset in the default space
	 * @param max the max byte offset in the default space
	 * @return the address range
	 */
	protected static AddressRange rng(Program program, long min, long max) {
		return new AddressRangeImpl(addr(program, min), addr(program, max));
	}

	protected static AddressRange rng(Address min, long length) throws AddressOverflowException {
		return new AddressRangeImpl(min, length);
	}

	protected static AddressSetView set(AddressRange... ranges) {
		AddressSet set = new AddressSet();
		for (AddressRange rng : ranges) {
			set.add(rng);
		}
		return set;
	}

	protected static AddressRange quantize(AddressRange rng, long page) {
		AddressSpace space = rng.getAddressSpace();
		long min = Long.divideUnsigned(rng.getMinAddress().getOffset(), page) * page;
		long max = Long.divideUnsigned(rng.getMaxAddress().getOffset() + page - 1, page) * page - 1;
		return new AddressRangeImpl(space.getAddress(min), space.getAddress(max));
	}

	public static Language getToyBE64Language() {
		try {
			return DefaultLanguageService.getLanguageService()
					.getLanguage(new LanguageID(LANGID_TOYBE64));
		}
		catch (LanguageNotFoundException e) {
			throw new AssertionError("Why is the Toy language missing?", e);
		}
	}

	// TODO: Propose this replace waitForProgram
	public static void waitForDomainObject(DomainObject object) {
		object.flushEvents();
		waitForSwing();
	}

	public interface ExRunnable {
		void run() throws Throwable;
	}

	protected static Runnable noExc(ExRunnable runnable) {
		return () -> {
			try {
				runnable.run();
			}
			catch (Throwable e) {
				throw new AssertionError(e);
			}
		};
	}

	public static void waitForPass(Runnable runnable) {
		AtomicReference<AssertionError> lastError = new AtomicReference<>();
		waitForCondition(() -> {
			try {
				runnable.run();
				return true;
			}
			catch (AssertionError e) {
				lastError.set(e);
				return false;
			}
		}, () -> lastError.get().getMessage());
	}

	public static void waitForPass(Object originator, Runnable runnable, long duration,
			TimeUnit unit) {
		long start = System.currentTimeMillis();
		while (System.currentTimeMillis() - start < unit.toMillis(duration)) {
			try {
				waitForPass(runnable);
				break;
			}
			catch (Throwable e) {
				Msg.warn(originator, "Long wait: " + e);
				try {
					Thread.sleep(500);
				}
				catch (InterruptedException e1) {
				}
			}
		}
	}

	public static <T> T waitForPass(Supplier<T> supplier) {
		var locals = new Object() {
			AssertionError lastError;
			T value;
		};
		waitForCondition(() -> {
			try {
				locals.value = supplier.get();
				return true;
			}
			catch (AssertionError e) {
				locals.lastError = e;
				return false;
			}
		}, () -> locals.lastError.getMessage());
		return locals.value;
	}

	protected static Set<String> getMenuElementsText(MenuElement menu) {
		Set<String> result = new HashSet<>();
		for (MenuElement sub : menu.getSubElements()) {
			Component comp = sub.getComponent();
			if (comp instanceof JPopupMenu) {
				return getMenuElementsText(sub);
			}
			JMenuItem item = (JMenuItem) sub.getComponent();
			result.add(item.getText());
		}
		return result;
	}

	protected static Set<String> getMenuElementsText() {
		MenuElement[] sel = runSwing(() -> MenuSelectionManager.defaultManager().getSelectedPath());
		if (sel == null || sel.length == 0) {
			return Set.of();
		}
		MenuElement last = sel[sel.length - 1];
		return getMenuElementsText(last);
	}

	protected static Set<String> intersection(Collection<String> a, Collection<String> b) {
		Set<String> result = new LinkedHashSet<>(a);
		result.retainAll(b);
		return Set.copyOf(result);
	}

	protected static void assertMenu(Set<String> cares, Set<String> expectedTexts) {
		waitForPass(() -> {
			assertEquals(expectedTexts, intersection(cares, getMenuElementsText()));
		});
	}

	protected static MenuElement getSubMenuElementByText(String text) {
		MenuElement[] sel = runSwing(() -> MenuSelectionManager.defaultManager().getSelectedPath());
		if (sel == null || sel.length == 0) {
			throw new NoSuchElementException("No menu is active");
		}
		MenuElement last = sel[sel.length - 1];
		for (MenuElement sub : last.getSubElements()) {
			JMenuItem item = (JMenuItem) sub.getComponent();
			if (text.equals(item.getText())) {
				return sub;
			}
		}
		throw new NoSuchElementException("No item with text " + text);
	}

	protected static void assertSubMenu(MenuElement sub, Set<String> cares,
			Set<String> expectedTexts) {
		waitForPass(() -> {
			assertEquals(expectedTexts, intersection(cares, getMenuElementsText(sub)));
		});
	}

	/**
	 * Find the sub menu item of the current selection by text
	 *
	 * Note that if the desired item is at the same level as the currently selected item, this
	 * method will not find it. It searches the sub menu of the currently selected item.
	 *
	 * @param text the text
	 * @return the found item
	 * @throws NoSuchElementException if the desired item is not found
	 */
	protected static JMenuItem getSubMenuItemByText(String text) {
		MenuElement sub = getSubMenuElementByText(text);
		return (JMenuItem) sub.getComponent();
	}

	/**
	 * Activate via mouse the sub menu item of the current selection by text
	 *
	 * @param text the text on the item to click
	 * @throws AWTException
	 * @throws NoSuchElementException if no item with the given text is found
	 */
	protected static void clickSubMenuItemByText(String text) throws Exception {
		JMenuItem item = getSubMenuItemByText(text);
		waitFor(() -> item.isShowing());

		Point isl = item.getLocationOnScreen();
		Rectangle b = item.getBounds();
		Point m = new Point(isl.x + b.width / 2, isl.y + b.height / 2);

		clickMouse(MouseEvent.BUTTON1, m);
	}

	/**
	 * Only use this to escape from pop-up menus. Otherwise, use {@link #triggerEscape(Component)}.
	 * 
	 * @throws AWTException
	 */
	protected static void pressEscape() throws AWTException {
		Robot robot = new Robot();
		robot.keyPress(KeyEvent.VK_ESCAPE);
		robot.keyRelease(KeyEvent.VK_ESCAPE);
	}

	protected static void escapePopupMenu() {
		waitForPass(noExc(() -> {
			pressEscape();
			assertEquals(0, runSwing(() -> {
				return MenuSelectionManager.defaultManager().getSelectedPath().length;
			}).intValue());
		}));
		waitForSwing();
	}

	protected static Point getViewportPosition(Component comp) {
		Component parent = comp.getParent();
		if (!(parent instanceof JViewport)) {
			return new Point(0, 0);
		}
		JViewport viewport = (JViewport) parent;
		return viewport.getViewPosition();
	}

	protected static void clickMouse(int button, Point m) throws Exception {
		Robot robot = new Robot();
		robot.mouseMove(m.x, m.y);
		int mask = InputEvent.getMaskForButton(button);
		robot.mousePress(mask);
		robot.mouseRelease(mask);
	}

	protected static void clickListItem(JList<?> list, int index, int button) throws Exception {
		list.ensureIndexIsVisible(index);
		waitForSwing();

		Rectangle b = list.getCellBounds(index, index);
		Point lsl = list.getLocationOnScreen();
		Point vp = getViewportPosition(list);
		Point m = new Point(lsl.x + b.x + b.width / 2 - vp.x, lsl.y + b.y + b.height / 2 - vp.y);

		clickMouse(button, m);
	}

	protected static void clickTreeNode(GTree tree, GTreeNode node, int button) throws Exception {
		TreePath path = node.getTreePath();
		tree.scrollPathToVisible(path);
		waitForSwing();

		Rectangle b = tree.getPathBounds(path);
		Point tsl = tree.getLocationOnScreen();
		Point vp = tree.getViewPosition();
		Point m = new Point(tsl.x + b.x + b.width / 2 - vp.x, tsl.y + b.y + b.height / 2 - vp.y);

		clickMouse(button, m);
	}

	protected static void clickTableCellWithButton(JTable table, int row, int col, int button)
			throws Exception {
		Rectangle b = table.getCellRect(row, col, false);
		table.scrollRectToVisible(b);
		waitForSwing();

		Point tsl = table.getLocationOnScreen();
		Point m = new Point(tsl.x + b.x + b.width / 2, tsl.y + b.y + b.height / 2);

		clickMouse(button, m);
	}

	protected static void assertListingBackgroundAt(Color expected, ListingPanel panel,
			Address addr, int yAdjust) throws AWTException, InterruptedException {
		ProgramLocation oneBack = new ProgramLocation(panel.getProgram(), addr.previous());
		runSwing(() -> panel.goTo(addr));
		runSwing(() -> panel.goTo(oneBack, false));
		waitForPass(() -> {
			Rectangle r = panel.getBounds();
			// Capture off screen, so that focus/stacking doesn't matter
			BufferedImage image = new BufferedImage(r.width, r.height, BufferedImage.TYPE_INT_ARGB);
			Graphics g = image.getGraphics();
			try {
				runSwing(() -> panel.paint(g));
			}
			finally {
				g.dispose();
			}
			Point locP = panel.getLocationOnScreen();
			Point locFP = panel.getLocationOnScreen();
			locFP.translate(-locP.x, -locP.y);
			Rectangle cursor = panel.getCursorBounds();
			assertNotNull("Cannot get cursor bounds", cursor);
			Color actual = new Color(image.getRGB(locFP.x + cursor.x - 1,
				locFP.y + cursor.y + cursor.height * 3 / 2 + yAdjust));
			assertEquals(expected.getRGB(), actual.getRGB());
		});
	}

	protected static void assertDisabled(ActionContextProvider provider, DockingActionIf action) {
		ActionContext context = provider.getActionContext(null);
		assertFalse(action.isEnabledForContext(context));
	}

	protected static void assertEnabled(ActionContextProvider provider, DockingActionIf action) {
		ActionContext context = provider.getActionContext(null);
		assertTrue(action.isEnabledForContext(context));
	}

	protected static void performEnabledAction(ActionContextProvider provider,
			DockingActionIf action, boolean wait) {
		ActionContext context = waitForValue(() -> {
			ActionContext ctx =
				provider == null ? new DefaultActionContext() : provider.getActionContext(null);
			if (!action.isEnabledForContext(ctx)) {
				return null;
			}
			return ctx;
		});
		performAction(action, context, wait);
	}

	protected static void goTo(ListingPanel listingPanel, ProgramLocation location) {
		waitForPass(() -> {
			runSwing(() -> listingPanel.goTo(location));
			ProgramLocation confirm = listingPanel.getCursorLocation();
			assertNotNull(confirm);
			assertEquals(location.getAddress(), confirm.getAddress());
		});
	}

	protected void select(Navigatable nav, Address min, Address max) {
		select(nav, new ProgramSelection(min, max));
	}

	protected void select(Navigatable nav, AddressSetView set) {
		select(nav, new ProgramSelection(set));
	}

	protected void select(Navigatable nav, ProgramSelection sel) {
		runSwing(() -> nav.setSelection(sel));
	}

	protected Object rowColVal(ValueRow row, DynamicTableColumn<ValueRow, ?, Trace> col) {
		if (col instanceof TraceValueObjectPropertyColumn<?> attrCol) {
			return attrCol.getValue(row, SettingsImpl.NO_SETTINGS, tb.trace, tool).getValue();
		}
		Object value = col.getValue(row, SettingsImpl.NO_SETTINGS, tb.trace, tool);
		return value;
	}

	protected <T> String rowColDisplay(ValueRow row, DynamicTableColumn<ValueRow, T, Trace> col) {
		T value = col.getValue(row, SettingsImpl.NO_SETTINGS, tb.trace, tool);
		return col.getColumnRenderer().getFilterString(value, SettingsImpl.NO_SETTINGS);
	}

	protected static LocationTrackingSpec getLocationTrackingSpec(String name) {
		return LocationTrackingSpecFactory.fromConfigName(name);
	}

	protected static AutoReadMemorySpec getAutoReadMemorySpec(String name) {
		return AutoReadMemorySpecFactory.fromConfigName(name);
	}

	protected final AutoReadMemorySpec readNone =
		getAutoReadMemorySpec(BasicAutoReadMemorySpec.NONE.getConfigName());
	protected final AutoReadMemorySpec readVisible =
		getAutoReadMemorySpec(BasicAutoReadMemorySpec.VISIBLE.getConfigName());
	protected final AutoReadMemorySpec readVisROOnce =
		getAutoReadMemorySpec(BasicAutoReadMemorySpec.VIS_RO_ONCE.getConfigName());

	protected TestEnv env;
	protected PluginTool tool;

	protected DebuggerTargetService targetService;
	protected DebuggerTraceManagerService traceManager;
	protected ProgramManager programManager;

	protected ToyDBTraceBuilder tb;
	protected Program program;

	@Rule
	public TestName name = new TestName();

	protected final ConsoleTaskMonitor monitor = new ConsoleTaskMonitor();

	@BeforeClass
	public static void beforeClass() {
		// Note: we decided to move this up to a framework-level base test class
		TestDataStructureErrorHandlerInstaller.installConcurrentExceptionErrorHandler();
	}

	@Before
	public void setUp() throws Exception {
		env = new TestEnv();
		tool = env.getTool();

		targetService = addPlugin(tool, DebuggerTargetServicePlugin.class);

		addPlugin(tool, DebuggerTraceManagerServicePlugin.class);
		traceManager = tool.getService(DebuggerTraceManagerService.class);

		programManager = tool.getService(ProgramManager.class);

		env.showTool();
	}

	@After
	public void tearDown() {
		try {
			waitForTasks();
			runSwing(() -> {
				if (traceManager == null) {
					return;
				}
				traceManager.setSaveTracesByDefault(false);
			});

			if (tb != null) {
				if (traceManager != null && traceManager.getOpenTraces().contains(tb.trace)) {
					traceManager.closeTraceNoConfirm(tb.trace);
				}
				tb.close();
			}

			if (program != null) {
				programManager.closeAllPrograms(true);
				program.release(this);
			}

			waitForTasks();
		}
		finally {
			env.dispose();
		}
	}

	protected void intoProject(DomainObject obj) {
		waitForDomainObject(obj);
		DomainFolder rootFolder = tool.getProject().getProjectData().getRootFolder();
		waitForCondition(() -> {
			try {
				rootFolder.createFile(obj.getName(), obj, monitor);
				return true;
			}
			catch (InvalidNameException | CancelledException e) {
				throw new AssertionError(e);
			}
			catch (IOException e) {
				// Usually "object is busy". Try again.
				return false;
			}
		});
	}

	protected void createSnaplessTrace(String langID) throws IOException {
		tb = new ToyDBTraceBuilder("dynamic-" + name.getMethodName(), langID);
	}

	protected void createSnaplessTrace() throws IOException {
		createSnaplessTrace(LANGID_TOYBE64);
	}

	protected void addSnapshot(String desc) throws IOException {
		try (Transaction tx = tb.startTransaction()) {
			tb.trace.getTimeManager().createSnapshot(desc);
		}
	}

	protected void createTrace(String langID) throws IOException {
		createSnaplessTrace(langID);
		addSnapshot("First snap");
	}

	protected void createTrace() throws IOException {
		createTrace(LANGID_TOYBE64);
	}

	protected void useTrace(Trace trace) {
		tb = new ToyDBTraceBuilder(trace);
	}

	protected void createAndOpenTrace(String langID) throws IOException {
		createTrace(langID);
		traceManager.openTrace(tb.trace);
	}

	protected void createAndOpenTrace() throws IOException {
		createAndOpenTrace(LANGID_TOYBE64);
	}

	protected String getProgramName() {
		return "static-" + getClass().getCanonicalName() + "." + name.getMethodName();
	}

	protected void createProgramFromTrace(Trace trace) throws IOException {
		createProgram(trace.getBaseLanguage(), trace.getBaseCompilerSpec());
	}

	protected void createProgramFromTrace() throws IOException {
		createProgramFromTrace(tb.trace);
	}

	protected void createProgram(Language lang, CompilerSpec cSpec) throws IOException {
		program = new ProgramDB(getProgramName(), lang, cSpec, this);
	}

	protected void createProgram(Language lang) throws IOException {
		createProgram(lang, lang.getDefaultCompilerSpec());
	}

	protected void createProgram() throws IOException {
		createProgram(getToyBE64Language());
	}

	protected void createAndOpenProgramFromTrace() throws IOException {
		createProgramFromTrace();
		programManager.openProgram(program);
	}

	protected void createAndOpenProgramWithExePath(String path) throws IOException {
		Language lang = getToyBE64Language();
		program = new ProgramDB("static-" + name.getMethodName(), lang,
			lang.getDefaultCompilerSpec(), this);
		try (Transaction tx = program.openTransaction("Set Executable Path")) {
			program.setExecutablePath(path);
		}
		programManager.openProgram(program);
	}

	protected File pack(DomainObject object) throws Exception {
		File tempDir = Files.createTempDirectory("ghidra-" + name.getMethodName()).toFile();
		File pack = new File(tempDir, "obj" + System.identityHashCode(object) + ".gzf");
		object.saveToPackedFile(pack, monitor);
		return pack;
	}

	protected DomainFile unpack(File pack) throws Exception {
		return tool.getProject()
				.getProjectData()
				.getRootFolder()
				.createFile("Restored", pack, monitor);
	}
}
