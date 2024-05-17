/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.app.plugin.core.format;

import ghidra.app.plugin.core.byteviewer.ByteViewerComponentProvider;
import ghidra.util.HelpLocation;

import java.math.BigInteger;
import java.util.Arrays;

/**
 * Converts byte values to C64 Charset representation.
 */

 public class C64CharsetUnshiftedFormatModel implements UniversalDataFormatModel {

	private int symbolSize;

	public C64CharsetUnshiftedFormatModel () {
		symbolSize = 1;
	}

	/**
	 * Get the name of this formatter.
	 */
	public String getName() {
		return "C64 Charset Unshifted";
	}

	/**
	 * Get the number of bytes to make a unit; in this case it
	 * takes 1 byte to make an Ascii value.
	 */
	public int getUnitByteSize() {
		return 1;
	}

	/**
	 * Given a character position from 0 to data unit symbol size - 1
	 * it returns a number from 0 to unit byte size - 1 indicating which
	 * byte the character position was obtained from.
	 */
	public int getByteOffset(ByteBlock block, int position) {
		return 0;
	}

	/**
	 * Given the byte offset into a unit, get the column position.
	 */
	public int getColumnPosition(ByteBlock block, int byteOffset) {
		return 0;
	}

	/**
	 * Gets the number of characters required to display a
	 * unit.
	 */
	public int getDataUnitSymbolSize() {
		return symbolSize;
	}

	/**
	 * Gets the string representation at the given index in the block.
	 * @param block block to change
	 * @param index byte index into the block
	 * @throws ByteBlockAccessException if the block cannot be read
	 * @throws IndexOutOfBoundsException if index is not valid for the
	 * block
	 */
	public String getDataRepresentation(ByteBlock block, BigInteger index)
			throws ByteBlockAccessException {
// Unicode13 Mappings for Retro Computing

			String[] Petscii = {
// First 128 characters are found in Unicode, mapping them accordingly
				"@", "a", "b", "c", "d", "e", "f", "g",
				"h", "i", "j", "k", "l", "m", "n", "o",
				"p", "q", "r", "s", "t", "u", "v", "w",
				"x", "y", "z", "[", "£", "]", "\u2191", "\u2190",
				" ", "!", "\"", "#", "$", "%", "&", "'",
				"(", ")", "*", "+", ",", "-", ".", "/",
				"0", "1", "2", "3", "4", "5", "6", "7",
				"8", "9", ":", ";", "<", "=", ">", "?",
				"\uD83E\uDF79", "A", "B", "C", "D", "E", "F", "G",
				"H", "I", "J", "K", "L", "M", "N", "O",
				"P", "Q", "R", "S", "T", "U", "V", "W",
				"X", "Y", "Z", "\u253C", "\uD83E\uDF8C", "\u2502", "\uD83E\uDF96", "\uD83E\uDF98",
				"\u00A0", "\u258C", "\u2584", "\u2594", "\u2581", "\u258F", "\u2592", "\u2595",
				"\uD83E\uDF8F", "\uD83E\uDF99", "\uD83E\uDF87", "\u251C", "\u2597", "\u2514", "\u2510", "\u2582",
				"\u250C", "\u2534", "\u252C", "\u2524", "\u258E", "\u258D", "\uD83E\uDF88", "\uD83E\uDF82",
				"\uD83E\uDF83", "\u2583", "\u2713", "\u2596", "\u259D", "\u2518", "\u2598", "\u259A",

// Inverted characters that follow cannot be found in Unicode, map for the C64 Pro Mono font.
/**			"\uEE80", "\uEE81", "\uEE82", "\uEE83", "\uEE84", "\uEE85", "\uEE86", "\uEE87", 
			"\uEE88", "\uEE89", "\uEE8A", "\uEE8B", "\uEE8C", "\uEE8D", "\uEE8E", "\uEE8F", 
			"\uEE90", "\uEE91", "\uEE92", "\uEE93", "\uEE94", "\uEE95", "\uEE96", "\uEE97", 
			"\uEE98", "\uEE99", "\uEE9A", "\uEE9B", "\uEE9C", "\uEE9D", "\uEE9E", "\uEE9F", 
			"\uEEA0", "\uEEA1", "\uEEA2", "\uEEA3", "\uEEA4", "\uEEA5", "\uEEA6", "\uEEA7", 
			"\uEEA8", "\uEEA9", "\uEEAA", "\uEEAB", "\uEEAC", "\uEEAD", "\uEEAE", "\uEEAF", 
			"\uEEB0", "\uEEB1", "\uEEB2", "\uEEB3", "\uEEB4", "\uEEB5", "\uEEB6", "\uEEB7", 
			"\uEEB8", "\uEEB9", "\uEEBA", "\uEEBB", "\uEEBC", "\uEEBD", "\uEEBE", "\uEEBF", 
			"\uEEC0", "\uEEC1", "\uEEC2", "\uEEC3", "\uEEC4", "\uEEC5", "\uEEC6", "\uEEC7", 
			"\uEEC8", "\uEEC9", "\uEECA", "\uEECB", "\uEECC", "\uEECD", "\uEECE", "\uEECF", 
			"\uEED0", "\uEED1", "\uEED2", "\uEED3", "\uEED4", "\uEED5", "\uEED6", "\uEED7", 
			"\uEED8", "\uEED9", "\uEEDA", "\uEEDB", "\uEEDC", "\uEEDD", "\uEEDE", "\uEEDF", 
			"\uEEE0", "\uEEE1", "\uEEE2", "\uEEE3", "\uEEE4", "\uEEE5", "\uEEE6", "\uEEE7", 
			"\uEEE8", "\uEEE9", "\uEEEA", "\uEEEB", "\uEEEC", "\uEEED", "\uEEEE", "\uEEEF", 
			"\uEEF0", "\uEEF1", "\uEEF2", "\uEEF3", "\uEEF4", "\uEEF5", "\uEEF6", "\uEEF7", 
			"\uEEF8", "\uEEF9", "\uEEFA", "\uEEFB", "\uEEFC", "\uEEFD", "\uEEFE", "\uEEFF"
*/
// Mappings for Pet Me font

			"\uE080", "\uE081", "\uE082", "\uE083", "\uE084", "\uE085", "\uE086", "\uE087", 
			"\uE088", "\uE089", "\uE08A", "\uE08B", "\uE08C", "\uE08D", "\uE08E", "\uE08F", 
			"\uE090", "\uE091", "\uE092", "\uE093", "\uE094", "\uE095", "\uE096", "\uE097", 
			"\uE098", "\uE099", "\uE09A", "\uE09B", "\uE09C", "\uE09D", "\uE09E", "\uE09F", 
			"\uE0A0", "\uE0A1", "\uE0A2", "\uE0A3", "\uE0A4", "\uE0A5", "\uE0A6", "\uE0A7", 
			"\uE0A8", "\uE0A9", "\uE0AA", "\uE0AB", "\uE0AC", "\uE0AD", "\uE0AE", "\uE0AF", 
			"\uE0B0", "\uE0B1", "\uE0B2", "\uE0B3", "\uE0B4", "\uE0B5", "\uE0B6", "\uE0B7", 
			"\uE0B8", "\uE0B9", "\uE0BA", "\uE0BB", "\uE0BC", "\uE0BD", "\uE0BE", "\uE0BF", 
			"\uE0C0", "\uE0C1", "\uE0C2", "\uE0C3", "\uE0C4", "\uE0C5", "\uE0C6", "\uE0C7", 
			"\uE0C8", "\uE0C9", "\uE0CA", "\uE0CB", "\uE0CC", "\uE0CD", "\uE0CE", "\uE0CF", 
			"\uE0D0", "\uE0D1", "\uE0D2", "\uE0D3", "\uE0D4", "\uE0D5", "\uE0D6", "\uE0D7", 
			"\uE0D8", "\uE0D9", "\uE0DA", "\uE0DB", "\uE0DC", "\uE0DD", "\uE0DE", "\uE0DF", 
			"\uE0E0", "\uE0E1", "\uE0E2", "\uE0E3", "\uE0E4", "\uE0E5", "\uE0E6", "\uE0E7", 
			"\uE0E8", "\uE0E9", "\uE0EA", "\uE0EB", "\uE0EC", "\uE0ED", "\uE0EE", "\uE0EF", 
			"\uE0F0", "\uE0F1", "\uE0F2", "\uE0F3", "\uE0F4", "\uE0F5", "\uE0F6", "\uE0F7", 
			"\uE0F8", "\uE0F9", "\uE0FA", "\uE0FB", "\uE0FC", "\uE0FD", "\uE0FE", "\uE0FF"


		};

		byte b = block.getByte(index);
		String str = null;
		str = Petscii[(b & 0xFF)];
		return str;
	}

	/**
	 * Returns true if the formatter allows values to be changed.
	 */
	public boolean isEditable() {
		return true;
	}

	/**
	 * Overwrite a value in a ByteBlock.
	 * @param block block to change
	 * @param index byte index into the block
	 * @param pos The position within the unit where c will be the
	 * new character.
	 * @param c new character to put at pos param
	 * @return true if the replacement is legal, false if the
	 * replacement value would not make sense for this format, e.g.
	 * attempt to put a 'z' in a hex unit.
	 * @throws ByteBlockAccessException if the block cannot be updated
	 * @throws IndexOutOfBoundsException if index is not valid for the
	 * block
	 */
	public boolean replaceValue(ByteBlock block, BigInteger index, int charPosition, char c)
			throws ByteBlockAccessException {

		if (charPosition != 0) {
			return false;
		}

		block.getByte(index);
		byte cb = (byte) c;

		if (cb < 0x20 || cb == 0x7f) {
			return false;
		}

		block.setByte(index, cb);
		return true;
	}

	/**
	 * Get number of units in a group. A group may represent
	 * multiple units shown as one entity. This format does not
	 * support groups.
	 * @throws UnsupportedOperationException 
	 */
	public int getGroupSize() {
		return 0;
	}

	/**
	 * Set the number of units in a group. This format does not
	 * support groups.
	 * @throws UnsupportedOperationException 
	 */
	public void setGroupSize(int groupSize) {
		throw new UnsupportedOperationException("groups are not supported");
	}

	/**
	 * Get the number of characters separating units.
	 */
	public int getUnitDelimiterSize() {
		return 0;
	}

	/**
	 * @see ghidra.app.plugin.core.format.DataFormatModel#validateBytesPerLine(int)
	 */
	public boolean validateBytesPerLine(int bytesPerLine) {
		return true;
	}

	/* (non-Javadoc)
	 * @see ghidra.app.plugin.format.DataFormatModel#getHelpLocation()
	 */
	public HelpLocation getHelpLocation() {
		return new HelpLocation("ByteViewerPlugin", "Petscii");
	}

	public void dispose() {
	}

	public boolean supportsProvider(ByteViewerComponentProvider provider) {
		return true;
	}
}
