/* Copyright 2017 - 2023 R. Thomas
 * Copyright 2017 - 2023 Quarkslab
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef LIEF_MACHO_LINKER_OPT_HINT_COMMAND_H
#define LIEF_MACHO_LINKER_OPT_HINT_COMMAND_H
#include <vector>
#include <ostream>

#include "LIEF/visibility.h"
#include "LIEF/types.hpp"
#include "LIEF/span.hpp"

#include "LIEF/MachO/LoadCommand.hpp"

namespace LIEF {
namespace MachO {

class BinaryParser;
class Builder;
class LinkEdit;

namespace details {
struct linkedit_data_command;
}

//! Class which represents the `LC_LINKER_OPTIMIZATION_HINT` command
class LIEF_API LinkerOptHint : public LoadCommand {
  friend class BinaryParser;
  friend class Builder;
  friend class LinkEdit;

  public:
  LinkerOptHint();
  LinkerOptHint(const details::linkedit_data_command& cmd);

  LinkerOptHint& operator=(const LinkerOptHint& copy);
  LinkerOptHint(const LinkerOptHint& copy);

  LinkerOptHint* clone() const override;

  //! Offset in the binary where the signature starts
  inline uint32_t data_offset() const {
    return data_offset_;
  }

  //! Size of the raw signature
  inline uint32_t data_size() const {
    return data_size_;
  }

  inline void data_offset(uint32_t offset) {
    data_offset_ = offset;
  }

  inline void data_size(uint32_t size) {
    data_size_ = size;
  }

  inline span<const uint8_t> content() const {
    return content_;
  }

  inline span<uint8_t> content() {
    return content_;
  }

  ~LinkerOptHint() override;

  bool operator==(const LinkerOptHint& rhs) const;
  bool operator!=(const LinkerOptHint& rhs) const;

  void accept(Visitor& visitor) const override;

  std::ostream& print(std::ostream& os) const override;

  static bool classof(const LoadCommand* cmd);

  private:
  uint32_t      data_offset_ = 0;
  uint32_t      data_size_   = 0;
  span<uint8_t> content_;

};

}
}
#endif
