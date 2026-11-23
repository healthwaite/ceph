#include "ops.hpp"

namespace perfw {

std::unique_ptr<Operation> make_load_op();
std::unique_ptr<Operation> make_put_object_op();
std::unique_ptr<Operation> make_list_objects_op();
std::unique_ptr<Operation> make_overwrite_op(bool versioned);
std::unique_ptr<Operation> make_delete_multi_op();
std::unique_ptr<Operation> make_list_delete_multi_op();
std::unique_ptr<Operation> make_get_object_op();
std::unique_ptr<Operation> make_mixed_ops_op();

std::unique_ptr<Operation> make_operation(const std::string &name)
{
  if (name == "load") return make_load_op();
  if (name == "run-put-object") return make_put_object_op();
  if (name == "run-list-objects") return make_list_objects_op();
  if (name == "run-put-object-overwrite") return make_overwrite_op(false);
  if (name == "run-put-object-overwrite-versioned") return make_overwrite_op(true);
  if (name == "run-list-delete-multi") return make_list_delete_multi_op();
  if (name == "run-delete-multi") return make_delete_multi_op();
  if (name == "run-get-object") return make_get_object_op();
  if (name == "run-mixed-ops") return make_mixed_ops_op();
  return nullptr;
}

}  // namespace perfw
