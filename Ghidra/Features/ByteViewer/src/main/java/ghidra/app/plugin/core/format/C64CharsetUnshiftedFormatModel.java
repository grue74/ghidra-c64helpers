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

			"\uE280", "\uE281", "\uE282", "\uE283", "\uE284", "\uE285", "\uE286", "\uE287", 
			"\uE288", "\uE289", "\uE28A", "\uE28B", "\uE28C", "\uE28D", "\uE28E", "\uE28F", 
			"\uE290", "\uE291", "\uE292", "\uE293", "\uE294", "\uE295", "\uE296", "\uE297", 
			"\uE298", "\uE299", "\uE29A", "\uE29B", "\uE29C", "\uE29D", "\uE29E", "\uE29F", 
			"\uE2A0", "\uE2A1", "\uE2A2", "\uE2A3", "\uE2A4", "\uE2A5", "\uE2A6", "\uE2A7", 
			"\uE2A8", "\uE2A9", "\uE2AA", "\uE2AB", "\uE2AC", "\uE2AD", "\uE2AE", "\uE2AF", 
			"\uE2B0", "\uE2B1", "\uE2B2", "\uE2B3", "\uE2B4", "\uE2B5", "\uE2B6", "\uE2B7", 
			"\uE2B8", "\uE2B9", "\uE2BA", "\uE2BB", "\uE2BC", "\uE2BD", "\uE2BE", "\uE2BF", 
			"\uE2C0", "\uE2C1", "\uE2C2", "\uE2C3", "\uE2C4", "\uE2C5", "\uE2C6", "\uE2C7", 
			"\uE2C8", "\uE2C9", "\uE2CA", "\uE2CB", "\uE2CC", "\uE2CD", "\uE2CE", "\uE2CF", 
			"\uE2D0", "\uE2D1", "\uE2D2", "\uE2D3", "\uE2D4", "\uE2D5", "\uE2D6", "\uE2D7", 
			"\uE2D8", "\uE2D9", "\uE2DA", "\uE2DB", "\uE2DC", "\uE2DD", "\uE2DE", "\uE2DF", 
			"\uE2E0", "\uE2E1", "\uE2E2", "\uE2E3", "\uE2E4", "\uE2E5", "\uE2E6", "\uE2E7", 
			"\uE2E8", "\uE2E9", "\uE2EA", "\uE2EB", "\uE2EC", "\uE2ED", "\uE2EE", "\uE2EF", 
			"\uE2F0", "\uE2F1", "\uE2F2", "\uE2F3", "\uE2F4", "\uE2F5", "\uE2F6", "\uE2F7", 
			"\uE2F8", "\uE2F9", "\uE2FA", "\uE2FB", "\uE2FC", "\uE2FD", "\uE2FE", "\uE2FF"


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
